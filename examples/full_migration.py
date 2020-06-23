import time


from incountry import SecretKeyAccessor, Storage


def get_secrets():
    return {
        {
            "currentVersion": 1,
            "secrets": [{"secret": "password0", "version": 0}, {"secret": "password1", "version": 1}],
        }
    }


COUNTRY = "us"
migration_complete = False

storage = Storage(
    api_key="<API_KEY>",
    environment_id="<ENVIRONMENT_ID>",
    secret_key_accessor=SecretKeyAccessor(get_secrets),
    encrypt=True,
)

while not migration_complete:
    migration_res = storage.migrate(country=COUNTRY, limit=50)
    if migration_res["total_left"] == 0:
        migration_complete = True
    time.sleep(1)
