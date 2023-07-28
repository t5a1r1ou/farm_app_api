docker-compose run \
  --entrypoint "poetry init \
    --name farm-app \
    --dependency fastapi \
    --dependency uvicorn[standard]" \
  farm-app