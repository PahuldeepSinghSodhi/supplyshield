import requests

API = "https://api.weather.example.invalid/v1"


def forecast(city: str) -> dict:
    return requests.get(f"{API}/forecast", params={"q": city}, timeout=10).json()
