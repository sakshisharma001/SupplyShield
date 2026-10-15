"""Safe XML parsing with xml.etree.ElementTree."""
import xml.etree.ElementTree as ET

def parse_svg_dimensions(svg_string: str):
    root = ET.fromstring(svg_string)
    return {
        "width": root.attrib.get("width"),
        "height": root.attrib.get("height"),
        "viewBox": root.attrib.get("viewBox")
    }
