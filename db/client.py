from pymongo import MongoClient

# Base de datos local
# db_client = MongoClient().local

# Base de datos remota
db_client = MongoClient(
    "mongodb+srv://test:test@cluster0.3pwsaix.mongodb.net/?retryWrites=true&w=majority").test
