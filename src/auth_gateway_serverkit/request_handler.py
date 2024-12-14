from typing import Any, Tuple, Optional, Dict
from fastapi import Request, status
from pydantic import ValidationError
import json


def parse_request_body_to_model(model):
    """
    Parse request body to model. handle both json and form data.
    :param model: Pydantic model
    :return: Tuple[Optional[Any], list] - parsed data and error messages
    """
    async def parser(request: Request) -> Tuple[Optional[Any], list]:
        try:
            if request.headers.get("content-type") == "application/json":
                json_data = await request.json()
            else:
                json_data = await request.form()
            parsed_data = model(**json_data)
            return parsed_data, []
        except ValidationError as e:
            error_messages = []
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                message = error["msg"].replace("Value error,", "")
                error_messages.append(f"{field}: {message}")
            return None, error_messages
        except Exception as e:
            return None, [f"An unexpected error occurred: {str(e)}"]

    return parser


def response(res=None, validation_errors=None, error=None, data=False):
    """
    Response handler. Return response based on the response status.
    :param res:
    :param validation_errors:
    :param error:
    :param data:
    :return: dict
    """
    if validation_errors:
        return {"message": ", ".join(validation_errors), "status_code": status.HTTP_400_BAD_REQUEST}
    if error:
        return {"message": f"Internal Server Error: {error}", "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR}
    if res:
        response_status = res.get("status")
        del res["status"]
        if response_status == "success":
            res["status_code"] = status.HTTP_200_OK
            return res
        if data:
            res["status_code"] = status.HTTP_404_NOT_FOUND
            return res
        res["status_code"] = status.HTTP_400_BAD_REQUEST
        return res


async def parse_request(request):
    """Parse request based on content type."""
    content_type = request.headers.get('content-type', '').lower()

    if 'application/json' in content_type:
        return await parse_json_request_data(request)
    else:
        return await parse_form_request(request)


async def parse_json_request_data(request):
    """Parse JSON request."""
    request_data = await request.json()
    return request_data, 'json'


async def parse_form_request(request):
    """Parse regular form-urlencoded request."""
    form = await request.form()
    request_data = {key: value for key, value in form.multi_items()}
    return request_data, 'form'


async def get_request_user(request: Request) -> Dict[str, Any]:
    str_user = request.headers.get("x-user")
    if str_user:
        user = json.loads(str_user)
        return user
    return {}
