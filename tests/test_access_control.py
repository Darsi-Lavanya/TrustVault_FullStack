import os
import tempfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Import app only after choosing an isolated database/upload directory.
import app as tv

class TrustVaultAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db, self.old_upload = tv.DB_PATH, tv.UPLOAD_DIR
        tv.DB_PATH = Path(self.tmp.name) / "test.db"
        tv.UPLOAD_DIR = Path(self.tmp.name) / "uploads"
        tv.UPLOAD_DIR.mkdir()
        tv.app.config["TESTING"] = True
        tv.app.config["WTF_CSRF_ENABLED"] = False
        tv.init_db()
        with tv.connect_db() as db:
            from werkzeug.security import generate_password_hash
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("owner_a",generate_password_hash("password-owner-a"),"owner",tv.now()))
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("viewer_b",generate_password_hash("password-viewer-b"),"viewer",tv.now()))
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("owner_c",generate_password_hash("password-owner-c"),"owner",tv.now()))
            db.execute("""INSERT INTO documents(original_name,stored_name,category,description,owner_id,size_bytes,uploaded_at,updated_at)
                          VALUES('private.txt','private.txt','HR','secret',2,6,?,?)""", (tv.now(),tv.now()))
            (tv.UPLOAD_DIR / "private.txt").write_text("secret")
            db.commit()
        self.client = tv.app.test_client()

    def tearDown(self):
        tv.DB_PATH, tv.UPLOAD_DIR = self.old_db, self.old_upload
        self.tmp.cleanup()

    def login(self, username, password):
        return self.client.post("/login", data={"username":username,"password":password}, follow_redirects=True)

    def test_unshared_user_cannot_view_document(self):
        self.login("viewer_b", "password-viewer-b")
        response = self.client.get("/documents/1")
        self.assertEqual(response.status_code, 403)

    def test_unshared_user_cannot_download_document(self):
        self.login("viewer_b", "password-viewer-b")
        response = self.client.get("/documents/1/download")
        self.assertEqual(response.status_code, 403)

    def test_non_owner_cannot_delete_document(self):
        self.login("owner_c", "password-owner-c")
        response = self.client.post("/documents/1/delete")
        self.assertEqual(response.status_code, 403)

    def test_shared_read_user_can_download_but_not_edit(self):
        with tv.connect_db() as db:
            db.execute("INSERT INTO permissions(document_id,user_id,access_level,granted_by,granted_at) VALUES(1,4,'read',2,?)", (tv.now(),))
            db.commit()
        self.login("owner_c", "password-owner-c")
        self.assertEqual(self.client.get("/documents/1/download").status_code, 200)
        response = self.client.post("/documents/1/edit", data={"name":"changed.txt","category":"HR"})
        self.assertEqual(response.status_code, 403)

if __name__ == "__main__":
    unittest.main()
