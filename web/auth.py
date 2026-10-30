from functools import wraps
from flask import abort
from flask_login import LoginManager, UserMixin, current_user
from database import db
login_manager = LoginManager()
login_manager.login_view = "login"
class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.role = row["role"]
        self.password_hash = row["password_hash"]
@login_manager.user_loader
def load_user(user_id):
    row = db.get_user_by_id(int(user_id))
    return User(row) if row else None
def admin_required(view_fn):
    """IVMP Phase 0: users.role has existed in the schema since the start,
    but nothing actually checked it - every logged-in user (any role) could
    hit every route, including changing the global risk-scoring weights.
    Apply this decorator (alongside @login_required, which still handles
    the "logged in at all" check) to routes that should be admin-only.
    """
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return view_fn(*args, **kwargs)
    return wrapped
