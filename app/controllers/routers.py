from fastapi import APIRouter
from app.routes import users, products, categories, orders

router = APIRouter()
router.include_router(users.router)
router.include_router(products.router)
router.include_router(categories.router)
router.include_router(orders.router)
