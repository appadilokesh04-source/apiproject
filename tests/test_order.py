def test_create_order_flow(client):
    resp = client.post("/api/users/register", json={"email":"buyer@example.com","password":"buyerpwd","full_name":"Buyer"})
    assert resp.status_code == 200
    resp2 = client.post("/api/users/login", data={"username":"buyer@example.com","password":"buyerpwd"})
    token = resp2.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    from app.config.database import SessionLocal
    from app.models.models import User
    from app.utils.security import get_password_hash, create_access_token
    session = SessionLocal()
    admin = User(email="admin2@example.com", hashed_password=get_password_hash("admin2"), is_admin=True)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    session.close()
    admin_token = create_access_token({"user_id": admin.id, "is_admin": True})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    p = {
        "name":"Necklace",
        "price":200.0,
        "stock":5
    }
    pr = client.post("/api/products", json=p, headers=admin_headers)
    assert pr.status_code == 200
    pid = pr.json()["id"]

    order_payload = {"items":[{"product_id": pid, "quantity": 2}], "address":"Somewhere"}
    resp3 = client.post("/api/orders", json=order_payload, headers=headers)
    assert resp3.status_code == 200
    data = resp3.json()
    assert data["total_price"] > 0
