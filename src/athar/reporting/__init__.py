"""Rendering layer: turns a Case into console, structured, or HTML output."""

from .custody import ChainOfCustody
from .html import render_html
from .structured import render_csv, render_data, render_json

__all__ = ["render_html", "render_json", "render_csv", "render_data", "ChainOfCustody"]
