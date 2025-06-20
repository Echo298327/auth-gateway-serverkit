""" http client utilities for making asynchronous HTTP requests using httpx. """
import httpx
from typing import Optional, Dict
from .logger import init_logger

logger = init_logger("utils.requests")


async def post(
    url: str,
    json: Optional[dict] = None,
    data: Optional[dict] = None,
    files: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout=20,
    connect=5
) -> dict:
    try:
        timeout = httpx.Timeout(timeout, connect=connect)
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            if json is not None:
                response = await client.post(url, json=json)
            elif files is not None or data is not None:
                response = await client.post(url, data=data, files=files)
            else:
                response = await client.post(url, data=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text} - URL: {url}")
        raise
    except Exception as e:
        logger.error(f"Request error: {e} - URL: {url}")
        raise


async def get(
    url: str,
    params: dict = None,
    headers: Optional[Dict[str, str]] = None,
    timeout=20,
    connect=5
) -> dict:
    try:
        timeout = httpx.Timeout(timeout, connect=connect)
        async with httpx.AsyncClient(headers=headers) as client:
            response = await client.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
        raise
    except Exception as e:
        logger.error(f"Request error: {e}")
        raise


async def delete(
    url: str,
    params: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout=20,
    connect=5
) -> dict:
    try:
        timeout = httpx.Timeout(timeout, connect=connect)
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            response = await client.delete(url, params=params)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text} - URL: {url}")
        raise
    except Exception as e:
        logger.error(f"Request error: {e} - URL: {url}")
        raise


async def put(
    url: str,
    json: Optional[dict] = None,
    data: Optional[dict] = None,
    files: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout=20,
    connect=5
) -> dict:
    try:
        timeout = httpx.Timeout(timeout, connect=connect)
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            if json is not None:
                response = await client.put(url, json=json)
            elif files is not None or data is not None:
                response = await client.put(url, data=data, files=files)
            else:
                response = await client.put(url, data=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text} - URL: {url}")
        raise
    except Exception as e:
        logger.error(f"Request error: {e} - URL: {url}")
        raise
