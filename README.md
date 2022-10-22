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
+ **상관계수**
	+ 상관계수를 구하기 위한 변수들의 배열을 선언한다. Sx와 Sxx는 파형 길이에 대한 값이다. 그래서 키 추측에 상관이 항상 계산할 수 있다.
	```
	//correlation 값을 구하기 위한 변수 배열 메모리 할당
	Sx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxy = (double*)calloc(endpoint - startpoint, sizeof(double));
	corrT = (double*)calloc(endpoint - startpoint, sizeof(double));
	//Sx,Sxx 값 계산
	for (i = 0; i < TraceNum; i++) {
		for (j = 0; j < endpoint - startpoint; j++) {
			Sx[j] += data[i][j];
			Sxx[j] += data[i][j] * data[i][j];
		}
	}
	```
+ **K1,0 ⊕ K1,1**
	+ SEED는 128비트의 평문을 64비트 평문 L, R로 나눠서 R이 F함수 안에서 또 32비트 평문 C, D로 나뉜다. 여기서 키는 64비트가 들어가서 32비트 Ki,0 , Ki,1로 나뉜다. CPA를 할 때는 키와 연산되는 R평문을 사용한다. 그리고 Sbox연산하고 나서의 중간 값을 CPA한다. Sbox연산을 할 때 값을 불러오는 과정에서 전력이 소비되어 더 잘나온다. 여기서 K1,0 , K1,1를 동시에 추측하려면 2^8 * 2^8을 계산해야하는데 비효율적이다. 그래서 두 키가 XOR연산 된 값을 동시에 추측한다. 첫 번 째 G함수에 CPA를 하면 K1,0 ⊕ K1,1 값을 얻을 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335501-60a45857-1aa6-4457-97c3-fe8b39c2c9d2.png)
	+ 위의 구조도에 대한 CPA를 구현하면 아래와 같다. 먼저 i를 8부터 11까지 반복한다. 8부터 반복하는 이유는 평문을 PT[0]~PT[15]까지 라고 했을 때 PT[8]~PT[15]에 대하여 CPA를 진행하기 때문이다. 다음으로 K1,0 ⊕ K1,1값을 추측한다. SEED 알고리즘에서 예를 들어 S2box에는 PT[8]과 PT[12]가 들어간다. 따라서 PT[8]일 경우에는 S2box 연산을 하고 PT[9]일 경우에는 S1box 연산을 한다. 첫 번 째 G함수에 대한 Sbox연산을 CPA하기 직전 단계까지 왔다.
	```
	for (i = 8; i < 12; i++) {
	double max = 0;
	int maxkey = 0;
	for (key = 0; key < 256; key++) {
		//printf("%d KEY\n", key);
		Sy = 0;
		Syy = 0;
		memset(Sxy, 0, sizeof(double) * (endpoint - startpoint));
		for (j = 0; j < TraceNum; j++) {
			//원래는 S2box[PT[8] ^ PT[12] ^ RK[0] ^ RK[4]]가 들어가지만 K1,0^K1,1된 값을 한번에 추측
			if (i % 2 == 1) {
				iv = SEED_S1box[plaintext[j][i] ^ plaintext[j][i + 4] ^ key];
			}
			else {
				iv = SEED_S2box[plaintext[j][i] ^ plaintext[j][i + 4] ^ key];
			}
	```
	+ Sbox 연산을 한 중간 값이 나왔다면 이에 대해 CPA를 진행한다. 여기서 해밍웨이트 값을 계산해야 하는데 1의 개수를 구하는 것이다. 다음으로 상관계수를 구하고 상관계수가 최대값이 되는 키 값을 저장한다. 그러면 K1,0 ⊕ K1,1값을 얻어낼 수 있다. 그런데 두 번째 G함수에 대해 CPA도 진행해야 하기 때문에 8비트짜리 키 4개를 32비트로 붙여서 변수에 저장한다.
	```
				hw_iv = 0;
			//해밍 웨이트 값 계산(1의 개수를 계산)
			for (k = 0; k < 8; k++)hw_iv += ((iv >> k) & 1);
			Sy += hw_iv;
			Syy += hw_iv * hw_iv;
			for (k = 0; k < endpoint - startpoint; k++) {
				Sxy[k] += hw_iv * data[j][k];
			}
		}
		//상관계수 파형 계산
		for (k = 0; k < endpoint - startpoint; k++) {
			corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / 
				sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
			if (fabs(corrT[k]) > max) { //상관계수 최대값 구하기
				maxkey = key;
				max = fabs(corrT[k]);
			}

		}

		sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\%02dth_block_%02x.corrtrace", _FOLD_, i - 8, key);
		if ((err = fopen_s(&wfp, buf, "wb")))
		{
			printf("File Open Error3!!\n");
		}
		fwrite(corrT, sizeof(double), endpoint - startpoint, wfp);
		fclose(wfp);
		printf(".");
	}
	printf("%02dth_block : maxkey(%02X),maxcorr(%lf)\n", i - 8, maxkey, max);
	xor_key += maxkey << (8 * (11 - i)); //8bit짜리 4개의 maxkey를 32bit xor_key에 저장
	```
	+ 결과 값을 보면 K1,0 ⊕ K1,1값이 D6 1B 41 8C가 나오는 걸 알 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335575-764376c8-116d-45e4-96f9-7be17b967fc8.png)
+ **K1,0**
	+ 앞에서 K1,0 ⊕ K1,1값을 구했다. K1,0을 얻기 위해선 두 번째 G함수에 대한 CPA가 필요하다. K1,0 ⊕ K1,1값을 알고 있다면 왼쪽으로 가는 화살표의 연산 값을 계산할 수 있다. 여기서 G함수에 들어가기 전에 덧셈 과정에서 문제가 있다. 4bytes값을 한번에 더할 때는 문제가 생기지 않지만, 1byte씩 덧셈할 때는 carry가 발생한다. 이 부분을 고려하여 구현한다. 그리고 두 번째 G함수에 대한 CPA까지 완료하고 나면 K1,0값을 얻을 수 있다. K1,0 ⊕ K1,1에 K1,0값을 XOR하면 K1,1도 얻을 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335606-9a9e39ab-de5c-4d4f-adef-ea94a7a7b35b.png)
	+ 코드를 보면 첫 번째 G함수를 거치고 나서 두 번째 G함수의 Sbox연산한 중간 값을 얻는다. 이 중간 값에 대해서 CPA를 진행하면 K1,0값을 얻을 수 있다.
	```
	//SEED_G(C^D^K1,0^K1,1)
	ULONG* temp = (ULONG*)calloc(TraceNum, sizeof(ULONG));
	for (i = 0; i < TraceNum; i++) {
		ULONG c = out_32bit(&plaintext[i][8]);
		ULONG d = out_32bit(&plaintext[i][12]);
		temp[i] = xor_key ^ c ^ d;
		SEED_G(&temp[i]);
	}

	ULONG leftkey = 0;
	for (i = 0; i < 4; i++) {
		//printf("%x\n", realkey);
		double max = 0;
		int maxkey = 0;
		for (key = 0; key < 256; key++) {
			//printf("%d KEY\n", key);
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * (endpoint - startpoint));
			for (j = 0; j < TraceNum; j++) {
				//라운드의 F함수안에 2번째 G함수에 대한 CPA
				ULONG c = out_32bit(&plaintext[j][8]);
				if (i % 2 == 1)
					//1byte씩 덧셈할 때는 1byte + 1byte의 값이 0xff가 넘었을 때를 고려해야함
					iv = SEED_S2box[(((c ^ (leftkey + (key << (8 * i)))) + temp[j]) >> (8 * i)) & 0xff];
				else
					iv = SEED_S1box[(((c ^ (leftkey + (key << (8 * i)))) + temp[j]) >> (8 * i)) & 0xff];
	```
	+ 두 번째 G함수의 Sbox 연산한 중간 값에 대해 상관계수를 구하고 K1,0을 찾는다.
	```
			hw_iv = 0;
			//해밍 웨이트 값 계산(1의 개수를 계산)
			for (k = 0; k < 8; k++)hw_iv += ((iv >> k) & 1);
			Sy += hw_iv;
			Syy += hw_iv * hw_iv;
			for (k = 0; k < endpoint - startpoint; k++) {
				Sxy[k] += hw_iv * data[j][k];
			}
		}
		//상관계수 파형 계산
		for (k = 0; k < endpoint - startpoint; k++) {
			corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / 
				sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
			if (fabs(corrT[k]) > max) { //상관계수 최대값 구하기
				maxkey = key;
				max = fabs(corrT[k]);
			}

		}

		sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\%02dth_block_%02x.corrtrace", _FOLD_, i, key);
		if ((err = fopen_s(&wfp, buf, "wb")))
		{
			printf("File Open Error3!!\n");
		}
		fwrite(corrT, sizeof(double), endpoint - startpoint, wfp);
		fclose(wfp);
		printf(".");
	}
	printf("%02dth_block : maxkey(%02X),maxcorr(%lf)\n", i, maxkey, max);
	leftkey += maxkey << (8 * i); //8bit짜리 4개로 된 maxkey를 32bit realkey에 저장
	//printf("%x\n", realkey);
	```
	+ 결과를 보면 1라운드 키가 2C1034D1 FA0B755D가 나온 것을 확인할 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335702-685d7bc5-bab8-4bd4-bc00-7feceaf68f6d.png)
	
