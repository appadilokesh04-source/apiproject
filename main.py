import os
import logging
import uvicorn
from fastapi import FastAPI, Request
from app.routes.users import router as users_router
from app.routes.products import router as products_router
from app.routes.orders import router as orders_router




from app.config.database import engine, Base 
from app.controllers.routers import router 
from app.middlewares.errors import exception_handler 

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("babafly")


Base.metadata.create_all(bind=engine)

app = FastAPI(title="BabaFly Backend")
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="BabaFly Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (you can restrict later)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.add_exception_handler(Exception, exception_handler)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info("%s %s", request.method, request.url)
    response = await call_next(request)
    logger.info("Status %s for %s %s", response.status_code, request.method, request.url)
    return response

if __name__ == "__main__":
    import os
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)

