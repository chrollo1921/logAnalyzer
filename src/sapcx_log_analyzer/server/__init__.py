"""Shared web app: several people upload Dynatrace exports and ask questions about them."""

from sapcx_log_analyzer.server.app import create_app, is_loopback

__all__ = ["create_app", "is_loopback"]
