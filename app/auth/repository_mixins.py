from . import models as auth_models


class UserClauseMixin:
    def append_user_flags(self, is_active, is_staff, is_superuser):
        if is_active is not None:  # False value is not passed
            self.statement = self.statement.where(
                auth_models.users.c.is_active == is_active
            )
        if is_staff is not None:
            self.statement = self.statement.where(
                auth_models.users.c.is_staff == is_staff
            )
        if is_superuser is not None:
            self.statement = self.statement.where(
                auth_models.users.c.is_superuser == is_superuser
            )

        return self.statement
