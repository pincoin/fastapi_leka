import asyncio

from base_command import BaseCommand


class ExampleTask(BaseCommand):
    async def run(self):
        from auth.repositories import TokenRepository, UserRepository

        user = await UserRepository().find_by_id(2)
        print(user)

        token = await TokenRepository().get("refresh:2")
        print(token)


async def main():
    await ExampleTask().run()


if __name__ == "__main__":
    asyncio.run(main())
