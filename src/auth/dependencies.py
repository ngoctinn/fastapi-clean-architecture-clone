from fastapi import Depends, HTTPException, status
from typing import List
from .service import get_current_user
from .schemas import TokenData


class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user_data: TokenData = Depends(get_current_user)) -> None:
        if not user_data.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User has no roles assigned.",
            )

        # Kiểm tra nếu user có vai trò 'admin' thì cho phép mọi quyền
        if "admin" in user_data.roles:
            return

        # Kiểm tra xem có vai trò nào của user nằm trong danh sách cho phép không
        is_allowed = any(role in self.allowed_roles for role in user_data.roles)

        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You do not have the required permissions. Allowed roles: {', '.join(self.allowed_roles)}",
            )
