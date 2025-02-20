# 基本构建命令 docker build -t [私有仓库地址]/[命名空间]/[镜像名]:[标签] .
docker build --build-arg GOPROXY=https://goproxy.cn -t nexus.fhatt.cn/qf-gitea:v1.23.4 .

docker push exus.fhatt.cn/qf-gitea:v1.23.4
