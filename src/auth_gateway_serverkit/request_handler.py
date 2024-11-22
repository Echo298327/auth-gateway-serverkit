from typing import Any, Tuple, Optional
from fastapi import Request, status
from pydantic import ValidationError


def parse_json_request_model(model):
    async def parser(request: Request) -> Tuple[Optional[Any], list]:
        try:
            json_data = await request.json()
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
    elif 'multipart/form-data' in content_type:
        return await parse_multipart_request(request)
    else:
        return await parse_form_request(request)


async def parse_json_request_data(request):
    """Parse JSON request."""
    request_data = await request.json()
    return request_data, 'json'


async def parse_multipart_request(request):
    """Parse multipart form-data request."""
    form = await request.form()
    request_data = {key: value for key, value in form.multi_items()}
    return request_data, 'multipart'


async def parse_form_request(request):
    """Parse regular form-urlencoded request."""
    form = await request.form()
    request_data = {key: value for key, value in form.multi_items()}
    return request_data, 'form'
