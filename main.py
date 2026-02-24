import streamlit as st
import pymongo
import os

# MongoDB secrets check
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    st.error('MongoDB connection string is not defined in environment variables.')
    st.stop()

client = pymongo.MongoClient(MONGO_URI)
db = client['leadbox']

# CSS for custom styling
st.markdown('<style>body {background-color: #f0f2f5;}</style>', unsafe_allow_html=True)

# Session state for user authentication
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# Login gate logic
if not st.session_state['logged_in']:
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        if username == 'admin' and password == 'password':
            st.session_state['logged_in'] = True
            st.success('Logged in successfully!')
        else:
            st.error('Invalid username or password')
    st.stop()

st.sidebar.title('Main Menu')

# Dropdowns with type-to-add functionality
allocated_to = st.sidebar.text_input('Allocated To')
if allocated_to == '':
    allocated_to = st.sidebar.selectbox('Select Allocated To', ['Option 1', 'Option 2'], index=0)

product_type = st.sidebar.text_input('Product Type')
if product_type == '':
    product_type = st.sidebar.selectbox('Select Product Type', ['Type 1', 'Type 2'], index=0)

# Page logic
st.sidebar.header('Pages')
page = st.sidebar.radio('Go to', ['Home', 'Settings', 'About'])

if page == 'Home':
    st.title('Welcome to the Leadbox!')
elif page == 'Settings':
    st.title('Settings Page')
elif page == 'About':
    st.title('About Page')