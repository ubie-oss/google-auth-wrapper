# Copyright 2025 Ubie, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os

import streamlit as st
from dotenv import load_dotenv
from google.oauth2 import credentials
from google.cloud import bigquery

from google_auth_wrapper.streamlit import google_oauth2_required

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

print("REDIRECT_URI: ", os.getenv("REDIRECT_URI"))


@google_oauth2_required
def main():
    st.title("Google OAuth2 Example App")

    if "token" in st.session_state and st.session_state.token:
        st.success("Login successful!")
        st.write(f"User ID: {st.session_state.user_id}")
        st.write(f"User Email: {st.session_state.user_email}")

        token = st.session_state.token
        if token:
            credentials_obj = credentials.Credentials(token["access_token"])
            bigquery_client = bigquery.Client(credentials=credentials_obj)
            st.write("BigQueryProject: ", bigquery_client.project)
            for dataset in bigquery_client.list_datasets():
                st.write(dataset.dataset_id)
    else:
        st.warning("Token not found. Please login.")


if __name__ == "__main__":
    main()
