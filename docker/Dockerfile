FROM python:3.13-alpine

WORKDIR /app

# Instalar Poetry
RUN pip install poetry

# Copiar proyecto
COPY ../app /app

# Instalar dependencias con Poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-root

# Lanzar la app con Poetry
CMD ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80", "--reload"]
