import aiohttp
from typing import Optional, Dict, Tuple
from .logger import init_logger

logger = init_logger("utils.aiohttp")


async def post(
    url: str,
    json: Optional[dict] = None,
    data: Optional[dict] = None,
    files: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
    connect: int = 5
) -> Tuple[int, str, dict]:
    """
    Make a POST request and return status code, response text, and JSON response.
    :return: Tuple of (status_code, response_text, json_response)
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=connect)
    async with aiohttp.ClientSession(timeout=timeout_obj, headers=headers) as session:
        if json is not None:
            async with session.post(url, json=json) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response
        elif files is not None or data is not None:
            async with session.post(url, data=data, files=files) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response
        else:
            async with session.post(url, data=data) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response


async def get(
    url: str,
    params: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
    connect: int = 5
) -> Tuple[int, str, dict]:
    """
    Make a GET request and return status code, response text, and JSON response.
    :return: Tuple of (status_code, response_text, json_response)
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=connect)
    async with aiohttp.ClientSession(timeout=timeout_obj, headers=headers) as session:
        async with session.get(url, params=params) as response:
            response_text = await response.text()
            try:
                json_response = await response.json()
            except:
                json_response = {}
            return response.status, response_text, json_response


async def delete(
    url: str,
    params: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
    connect: int = 5
) -> Tuple[int, str, dict]:
    """
    Make a DELETE request and return status code, response text, and JSON response.
    :return: Tuple of (status_code, response_text, json_response)
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=connect)
    async with aiohttp.ClientSession(timeout=timeout_obj, headers=headers) as session:
        async with session.delete(url, params=params) as response:
            response_text = await response.text()
            try:
                json_response = await response.json()
            except:
                json_response = {}
            return response.status, response_text, json_response


async def put(
    url: str,
    json: Optional[dict] = None,
    data: Optional[dict] = None,
    files: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
    connect: int = 5
) -> Tuple[int, str, dict]:
    """
    Make a PUT request and return status code, response text, and JSON response.
    :return: Tuple of (status_code, response_text, json_response)
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=connect)
    async with aiohttp.ClientSession(timeout=timeout_obj, headers=headers) as session:
        if json is not None:
            async with session.put(url, json=json) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response
        elif files is not None or data is not None:
            async with session.put(url, data=data, files=files) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response
        else:
            async with session.put(url, data=data) as response:
                response_text = await response.text()
                try:
                    json_response = await response.json()
                except:
                    json_response = {}
                return response.status, response_text, json_response 