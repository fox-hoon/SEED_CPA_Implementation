# SEED_CPA_Implementation
* **CPA(Correlation Power Analysis)**
  * Power analysis attacks consume power/electromagnetic waves depending on data values and computational code values calculated inside the equipment, and generally rely on Hamming weights of data to consume power/electromagnetic waves.
  * CPA is a method of guessing the key by obtaining the correlation coefficient.
  * Power consumption is proportional to the number of 1 intermediate values in the operation.
  * If the key guess is correct, the correlation coefficient is high.
***
#SEED CPA
+ **CPA**
  + **Coreelation Power Analysis**
    + 전력분석 공격은 장비 내부에서 연산되는 데이터 값, 연산코드 값에 의존해 전력/전자파를 소비하고, 일반적으로 데이터의 해밍웨이트에 의존하여 전력/전자파를 소비한다.
    + CPA는 상관계수를 구하여 키를 추측하는 방식이다.
    + 전력 소모량이 연산 중간 값의 1의 수에 비례한다.
    + 키 추측이 옳은 경우 상관계수가 높다.
+ **SEED**
  + **SEED 128**
    + 1999년 2월 한국정보보호센터(現 한국정보보호진흥원)에서 개발한 SEED는 민간 부분인 인터넷, 전자상거래, 무선 통신 등에서 공개 시에 민감한 영향을 미칠 수 있는 정보의 보호와 개인 프라이버시 등을 보호하기 위하여 개발된 블록암호알고리즘이다.
    + 대칭키 블록 암호알고리즘은 비밀성을 제공하는 암호시스템의 중요 요소이다. n비트 블록 암호알고리즘이란 고정된 n비트 평문을 같은 길이의 n비트 암호문으로 바꾸는 함수를 말한다(n비트 : 블록 크기). 이러한 변형 과정에 암․복호키가 작용하여 암호화와 복호화를 수행한다.
    + Feistel 구조란 각각 n/2트인 L 0,R0 블록으로 이루어진 n비트 평문 블록 (L0 ,R0)이 r라운드( r≥1)를 거쳐 암호문 (Lr ,Rr)으로 변환되는 반복 구조이다.
+ **파형 분석**
  + **SEED.traces**
    + 아래 사진은 정렬된 SEED.traces 파형이고 총 1,000개의 파형으로 구성되어 있다. 정렬을 해주는 이유는 CPA를 할 때 정확성을 높이기 위함이다. 해당 파형은 연산과정에서 전력 소모량에 따라 파형이 다르게 나타난다. 이 파형을 분석하고 상관계수를 구해서 Key를 추측하는 방식이 CPA이다.
    
    ![제목 없음](https://user-images.githubusercontent.com/84726924/197335206-2dc0d031-a3ed-44e8-ad81-cbcee325db25.png)
    + SEED 파형 하단을 확대해 보면 아래와 같이 16번 반복되는 패턴을 확인할 수 있다. 이 부분이 16라운드 암호화과정이다. 이렇게 분석한 파형을 통해 CPA를 진행한다. 그리고 각 라운드 파형을 확인해서 CPA를 할 시작점과 끝점을 찾을 수 있다. 1라운드의 파형을 보면 약 485,000부터 500,000까지인 걸 확인할 수 있다.
    
    ![제목 없음](https://user-images.githubusercontent.com/84726924/197335223-28a40964-f0c7-41ff-aed5-4b5669ed713b.png)
***
# SEED CPA 구현
+ **trace file**
  + 첫 번째로 SEED.traces 파일을 읽어온다. SEED.traces 파일의 용량이 커서 메모리에 다 올라가지 않아 data에 담길 파형 길이를 조절한다. 즉, 각 라운드에서 사용할 파형 범위만큼을 할당한다.
  ```
  void read_file_trace(void) {
	char buf[256];
	int err, i, j;
	FILE* rfp;
	rfp = fopen("C:\\", "rb"); //trace 위치
	if (rfp == NULL) {
		printf("File Open Error1!!\n");
	}
	fread(&TraceLength, 4, 1, rfp);
	fread(&TraceNum, 4, 1, rfp);

	float* trace;
	trace = (float*)calloc(TraceLength, sizeof(float));
	data = (float**)calloc(TraceNum, sizeof(float*));
	for (i = 0; i < TraceNum; i++) {
		//파형을 startpoint~endpoint 값 만큼만 읽음
		data[i] = (float*)calloc(endpoint - startpoint, sizeof(float));
		fread(trace, 4, TraceLength, rfp);
		for (j = 0; j < endpoint - startpoint; j++) {
			data[i][j] = trace[j + startpoint];
		}
	}
	fclose(rfp);
	free(trace);
	
  }
  ```
+ **plaintext file**
  + 평문 파일을 읽어온다. plaintext.txt안에 평문을 보면 한 줄에 32bytes씩 되어 있다. 거기에 개행 문자 2bytes씩 추가로 붙어있기 때문에 총 34bytes씩을 읽어서 버퍼에 담고 34bytes중에 32bytes를 16bytes씩 나눠서 plaintext에 저장한다. 
  ```
  void read_file_plaintext(void) {
	unsigned char x, y, temp[34];
	char buf[256] = { 0 };
	int err, i, j;
	FILE* rfp;
	rfp = fopen("C:\\", "rb"); //평문 위치
	if (rfp == NULL) {
		printf("File Open Error2!!\n");
	}
	plaintext = (unsigned char**)calloc(TraceNum, sizeof(unsigned char*));
	for (i = 0; i < TraceNum; i++) {
		fread(buf, 1, 34, rfp);//-->16bytes로 바꿔서 plaintext[i]에 저장 필요
		plaintext[i] = (unsigned char*)calloc(16, sizeof(unsigned char));
		for (j = 0; j < 16; j++) {
			x = buf[2 * j];
			y = buf[2 * j + 1];
			//순차적으로 문자열 처리 ex)x=15,y=16...
			if (x >= 'A' && x <= 'Z')x = x - 'A' + 10; //'0'~'9','A'~'F','a'~'f'
			else if (x >= 'a' && x <= 'z')x = x - 'a' + 10;
			else if (x >= '0' && x <= '9')x -= '0';
			if (y >= 'A' && y <= 'Z')y = y - 'A' + 10; //'0'~'9','A'~'F','a'~'f'
			else if (y >= 'a' && y <= 'z')y = y - 'a' + 10;
			else if (y >= '0' && y <= '9')y -= '0';
			plaintext[i][j] = x * 16 + y;
		}
	}
	fclose(rfp);
	
  }
  ```
