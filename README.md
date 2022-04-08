# identity

#### build image and push to registry
```
docker build -t davidwahid/identity:latest . --platform linux/amd64 && docker push davidwahid/identity:latest
```

#### update container when source changes
```
docker pull davidwahid/identity && docker-compose up -d --no-deps auth
```