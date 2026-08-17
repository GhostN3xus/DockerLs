from __future__ import annotations

from dockerls.application.services.ecosystems import (
    detect_ecosystem_and_version,
    get_ecosystem_insights,
)


def test_detect_node_22():
    eco, ver, distro = detect_ecosystem_and_version("node:22-alpine")
    assert eco == "node"
    assert "22" in ver
    assert distro == "alpine"

    insights = get_ecosystem_insights("node:22-alpine")
    assert insights.ecosystem == "Node.js"
    assert any("musl" in a for a in insights.base_distro_advice)
    assert any("NODE_ENV=production" in s for s in insights.security_guidelines)
    assert any("USER node" in snip for snip in insights.recommended_dockerfile_snippets)


def test_detect_python_312():
    eco, ver, distro = detect_ecosystem_and_version("python:3.12-slim-bookworm")
    assert eco == "python"
    assert "3.12" in ver
    assert distro == "debian-slim"

    insights = get_ecosystem_insights("python:3.12-slim-bookworm")
    assert insights.ecosystem == "Python"
    assert any("PYTHONUNBUFFERED=1" in s for s in insights.security_guidelines)


def test_detect_go():
    eco, ver, distro = detect_ecosystem_and_version("golang:1.23-alpine")
    assert eco == "go"
    insights = get_ecosystem_insights("golang:1.23-alpine")
    assert insights.ecosystem == "Go"
    assert any("scratch" in a for a in insights.base_distro_advice)


def test_detect_java_temurin():
    eco, ver, distro = detect_ecosystem_and_version("eclipse-temurin:21-jre-alpine")
    assert eco == "java"
    insights = get_ecosystem_insights("eclipse-temurin:21-jre-alpine")
    assert insights.ecosystem == "Java / JVM"
    assert any("MaxRAMPercentage" in s for s in insights.security_guidelines)


def test_detect_rust():
    eco, ver, distro = detect_ecosystem_and_version("rust:1.82-alpine")
    assert eco == "rust"
    insights = get_ecosystem_insights("rust:1.82-alpine")
    assert insights.ecosystem == "Rust"


def test_detect_php():
    eco, ver, distro = detect_ecosystem_and_version("php:8.3-fpm-alpine")
    assert eco == "php"
    insights = get_ecosystem_insights("php:8.3-fpm-alpine")
    assert insights.ecosystem == "PHP"
