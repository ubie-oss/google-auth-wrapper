# Google Auth Wrapper

Wrappers for Google OAuth2.

## How to use

### Install

```shell
pip install git+https://github.com/ubie-oss/google-auth-wrapper
```

### Streamlit

The wrapper requires the environment variables:

- `GOOGLE_CLIENT_ID`: The client ID for the Google OAuth2 client.
- `GOOGLE_CLIENT_SECRET`: The client secret for the Google OAuth2 client.
- `REDIRECT_URI`: The redirect URI for the Google OAuth2 client.
    - We have to set the redirect URI exactly same as the one in the Google OAuth2 client.

Please refer to [the example](./example/google_oauth_streamlit.py) for more details.
