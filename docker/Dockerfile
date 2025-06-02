FROM python:3.13-alpine

WORKDIR /app

RUN pip install poetry

COPY app/pyproject.toml app/poetry.lock ./

RUN poetry config virtualenvs.create false \
  && poetry install --no-root

CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80", "--reload"]
