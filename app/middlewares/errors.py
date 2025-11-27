from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import status
import traceback
import logging

logger = logging.getLogger("uvicorn.error")

async def exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", traceback.format_exc())
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Internal server error"})
