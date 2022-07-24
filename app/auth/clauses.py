from . import models as auth_models


def appendUserFlags(statement, is_active, is_staff, is_superuser):
    if is_active is not None:  # False value is not passed
        statement = statement.where(auth_models.users.c.is_active == is_active)
    if is_staff is not None:
        statement = statement.where(auth_models.users.c.is_staff == is_staff)
    if is_superuser is not None:
        statement = statement.where(auth_models.users.c.is_superuser == is_superuser)

    return statement
