def test_user_registration_and_login(client):
    resp = client.post("/api/users/register", json={"email":"test@example.com","password":"strongpass","full_name":"Test User"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "test@example.com"

    resp2 = client.post("/api/users/login", data={"username":"test@example.com","password":"strongpass"})
    assert resp2.status_code == 200
    t = resp2.json()
    assert "access_token" in t