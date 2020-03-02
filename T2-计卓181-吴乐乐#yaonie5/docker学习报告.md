# docker学习报告

## 学习内容

docker安装     docker镜像加速     docker容器使用     docker镜像使用     docker容器连接     docker仓库管理     Dockerfile基本知识     docker-compose基本知识     docker命令大全     参考教程：[菜鸟教程](https://www.runoob.com/docker/docker-tutorial.html)

## 学习总结

1. Docker 可以让开发者打包他们的应用以及依赖包到一个轻量级、可移植的容器中，然后发布到任何流行的 Linux 机器上，也可以实现虚拟化。容器是完全使用沙箱机制，相互之间不会有任何接口,更重要的是容器性能开销极低。根据docker的这些特性，可以使用docker部署pwn的题目，既方便又安全。

2. 使用docker部署pwn题，首先要了解容器和镜像之间的关系，容器与镜像的关系类似于面向对象编程中的对象与类。其次了解Dockerfile的书写方式和docker-compose的基本使用方法。
3. 去github上找了两个部署pwn题的项目[pwn_deploy_chroot](https://github.com/giantbranch/pwn_deploy_chroot)和[ctf_xinetd](https://github.com/Eadom/ctf_xinetd)

## 学习感想

做一个东西前环境的部署很重要，环境部署好了才可以在上面进行操作与学习，还有就是要学会工具的使用，自己不会的要去各大平台上找大佬做好的项目，从他们的项目中去学习一个东西的制作流程。