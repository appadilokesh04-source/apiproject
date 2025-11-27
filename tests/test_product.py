def test_create_and_fetch_product(client):
    from app.config.database import SessionLocal
    from app.models.models import User
    from app.utils.security import get_password_hash, create_access_token
    session = SessionLocal()
    admin = User(email="admin@example.com", hashed_password=get_password_hash("adminpass"), is_admin=True)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    session.close()

    token = create_access_token({"user_id": admin.id, "is_admin": True})
    headers = {"Authorization": f"Bearer {token}"}
    product_payload = {
        "name":"Ring",
        "description":"Gold ring",
        "price":100.0,
        "discount":5.0,
        "stock":10,
        "rating":4.5,
        "metal_type":"gold",
        "polish_type":"matte",
        "image_url":"http://example.com/img.jpg"
    }
    resp = client.post("/api/products", json=product_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Ring"

    pid = data["id"]
    resp2 = client.get(f"/api/products/{pid}")
    assert resp2.status_code == 200
    assert resp2.json()["name"] == "Ring"

