from html.parser import HTMLParser
from io import StringIO
from typing import Set

class XSSSanitizer(HTMLParser):
    def __init__(self, allowed_tags: Set[str] = None, allowed_attrs: Set[str] = None):
        super().__init__()
        self.allowed_tags = allowed_tags if allowed_tags is not None else set()
        self.allowed_attrs = allowed_attrs if allowed_attrs is not None else set()
        self.result = StringIO()
        
        self.disallowed_attr_prefixes = ("on", "javascript:", "data:", "vbscript:")
        # Block text rendering if inside completely banned execution tags
        self.banned_content_tags = {"script", "style", "iframe", "object", "embed"}
        self.current_stack = []

    def handle_starttag(self, tag, attrs):
        lower_tag = tag.lower()
        self.current_stack.append(lower_tag)
        
        if lower_tag in self.allowed_tags and not self._inside_banned_tag():
            cleaned_attrs = []
            for attr, val in attrs:
                if attr.lower().startswith(self.disallowed_attr_prefixes) or \
                   (val and any(val.lower().strip().startswith(p) for p in self.disallowed_attr_prefixes)):
                    continue
                if attr in self.allowed_attrs:
                    cleaned_attrs.append(f'{attr}="{val}"')
            
            attr_str = f" {' '.join(cleaned_attrs)}" if cleaned_attrs else ""
            self.result.write(f"<{tag}{attr_str}>")

    def handle_endtag(self, tag):
        lower_tag = tag.lower()
        if self.current_stack and self.current_stack[-1] == lower_tag:
            self.current_stack.pop()
        elif lower_tag in self.current_stack:
            # Handle unclosed tags cleanly
            while self.current_stack and self.current_stack[-1] != lower_tag:
                self.current_stack.pop()
            if self.current_stack:
                self.current_stack.pop()

        if lower_tag in self.allowed_tags and not self._inside_banned_tag():
            self.result.write(f"</{tag}>")

    def handle_data(self, data):
        if not self._inside_banned_tag():
            self.result.write(data)

    def _inside_banned_tag(self) -> bool:
        return any(t in self.banned_content_tags for t in self.current_stack)

    def get_clean_html(self) -> str:
        return self.result.getvalue()


def sanitize_html(text: str, allowed_tags: Set[str] = None, allowed_attrs: Set[str] = None) -> str:
    """Parses HTML and preserves allowed markup while removing executable elements."""
    parser = XSSSanitizer(allowed_tags, allowed_attrs)
    parser.feed(text)
    return parser.get_clean_html()

def strip_xss(text: str) -> str:
    """Aggressive fallback: completely strips ALL HTML tags and their inner malicious blocks."""
    return sanitize_html(text, allowed_tags=set(), allowed_attrs=set())