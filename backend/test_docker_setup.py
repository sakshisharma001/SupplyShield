"""
SupplyShield - Day 12 Automated Test Suite for Docker Containerization & Health Probes
Tests FastAPI /api/health endpoint, Dockerfile syntax, docker-compose configuration, and .dockerignore settings.
"""

import os
import unittest
from fastapi.testclient import TestClient

try:
    from backend.main import app
except ImportError:
    from main import app

client = TestClient(app)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestDockerContainerization(unittest.TestCase):

    def test_health_check_endpoint(self):
        """Verifies GET /api/health returns 200 OK and status HEALTHY."""
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("engines", data)
        self.assertEqual(data["engines"]["ast_analyzer"], "ONLINE")
        self.assertIn("version", data)


    def test_dockerfile_existence_and_content(self):
        """Verifies Dockerfile exists and contains required directives."""
        dockerfile_path = os.path.join(ROOT_DIR, "Dockerfile")
        self.assertTrue(os.path.exists(dockerfile_path), "Dockerfile does not exist in project root.")
        
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("FROM python:3.10-slim", content)
        self.assertIn("WORKDIR /app", content)
        self.assertIn("EXPOSE 8000", content)
        self.assertIn("HEALTHCHECK", content)
        self.assertIn("uvicorn", content)

    def test_docker_compose_existence_and_content(self):
        """Verifies docker-compose.yml exists and configures the supplyshield-engine service."""
        compose_path = os.path.join(ROOT_DIR, "docker-compose.yml")
        self.assertTrue(os.path.exists(compose_path), "docker-compose.yml does not exist in project root.")

        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("services:", content)
        self.assertIn("8000:8000", content)
        self.assertIn("healthcheck:", content)

    def test_dockerignore_content(self):
        """Verifies .dockerignore exists and excludes pycache and sensitive files."""
        dockerignore_path = os.path.join(ROOT_DIR, ".dockerignore")
        self.assertTrue(os.path.exists(dockerignore_path), ".dockerignore does not exist in project root.")

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("__pycache__/", content)
        self.assertIn(".git/", content)


if __name__ == "__main__":
    unittest.main()
