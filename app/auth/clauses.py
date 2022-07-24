from . import models as auth_models


def appendUserFlags(statement, is_active, is_staff, is_superuser):
    if is_active:
        statement = statement.where(auth_models.users.c.is_active == is_active)
    if is_staff:
        statement = statement.where(auth_models.users.c.is_staff == is_staff)
    if is_superuser:
        statement = statement.where(auth_models.users.c.is_superuser == is_superuser)

    return statement
