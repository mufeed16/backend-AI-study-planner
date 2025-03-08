from langchain_community.document_loaders import PyPDFLoader, DirectoryLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
import os
from config import DATA_DIR

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_vector_db():
    try:
        logging.info(f"Scanning directory for PDFs: {DATA_DIR}")
        loader = DirectoryLoader(DATA_DIR, glob="*.pdf", loader_cls=PyPDFLoader)
        documents = loader.load()
        logging.info(f"Number of documents loaded: {len(documents)}")
        embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2",
                                          model_kwargs={'device': 'cpu'})
        
        db = FAISS.from_documents(documents, embeddings)
        db.save_local("vectorstore/db_faiss")
        logging.info("Vector database created successfully.")
    except Exception as e:
        logging.error(f"Error creating vector database: {e}")

if __name__ == "__main__":
    create_vector_db()
