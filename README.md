# 기술 스택
### ✔Programming Language
<img src="https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=C&logoColor=white">

### ✔Tool
<img src="https://img.shields.io/badge/Visual Studio-5C2D91?style=for-the-badge&logo=Visual Studio&logoColor=white">

***
# SEED_CPA_Implementation
* **CPA(Correlation Power Analysis)**
  * Power analysis attacks consume power/electromagnetic waves depending on data values and computational code values calculated inside the equipment, and generally rely on Hamming weights of data to consume power/electromagnetic waves.
  * CPA is a method of guessing the key by obtaining the correlation coefficient.
  * Power consumption is proportional to the number of 1 intermediate values in the operation.
  * If the key guess is correct, the correlation coefficient is high.
***
# SEED CPA
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
+ **1라운드 암호화**
	+ 2라운드 키를 찾기 위해선 1라운드 암호화를 진행해야한다. 암호화는 알고리즘 그대로 진행하면 되고 굳이 2라운드의 Left평문을 구해줄 필요는 없다. 왜냐하면 2라운드 Right평문이 F함수에 들어가고 그 F함수 중간에서 CPA 진행 후 K2,0 , K2,1값을 구하기 때문이다. 2라운드 키를 얻는 방법은 1라운드와 동일하다.
	```
	void Round1_ENC(ULONG key0, ULONG key1) {
	for (int i = 0; i < TraceNum; i++) {
		ULONG L[2] = { 0 }, R[2] = { 0 }, temp[2];
		ULONG K[2] = { key0, key1 };
		//L,R로 평문을 나눔
		L[0] = out_32bit(&plaintext[i][0]);
		L[1] = out_32bit(&plaintext[i][4]);
		R[0] = out_32bit(&plaintext[i][8]);
		R[1] = out_32bit(&plaintext[i][12]);
		//F함수
		temp[0] = R[0] ^ K[0];
		temp[1] = R[1] ^ K[1];

		temp[1] ^= temp[0];

		SEED_G(temp + 1);
		temp[0] += temp[1];

		SEED_G(temp);
		temp[1] += temp[0];

		SEED_G(temp + 1);
		temp[0] += temp[1];

		L[0] ^= temp[0];
		L[1] ^= temp[1];
		//Left->Right
		//Right->Left는 필요없음. 2라운드 F함수에서 CPA가 완료됨
		plaintext[i][11] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][10] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][9] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][8] = L[0] & 0xff;
		plaintext[i][15] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][14] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][13] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][12] = L[1] & 0xff;
	}
	}
	```
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335810-8f1bf4fe-1a17-432e-9bf6-ad373353759f.png)
+ **K2,0 K2,1**
	+ 1라운드 암호화 후 1라운드와 동일한 방식으로 CPA를 하면 2라운드 키 0F0F8713 114B07B6을 얻을 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335834-0e8b5241-64f3-4bf7-9649-cc99b3dc74e4.png)
	+ K2,0값 중에 01블록에 87을 보면 일부분에서 파형이 튀는 걸 확인할 수 있다. 상관계수가 높지 않다면 저렇게 튀는 부분이 없다. 그러한 점이 보인다면 잘못된 키이다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335856-c390147c-582a-4442-ac81-78954b94b6a1.png)
+ **마스터 키**
	+ 먼저 X,Y,Z,V까지는 Inv G함수연산 후 라운드 상수와 덧셈, 뺄셈 연산으로 구할 수 있다. 그리고 (X=A+C, Y=B-D, Z=A′+C, V=B′-D) ↔ (X-Z=A-A′, Y-V=B-B′)이다. 그래서 1byte 변수들에 A-A′, B-B′을 각 각 1byte씩 쪼개서 담는다. (A-A′)|(B-B′)=(A|B)-(A′|B′)가 되는데 (A-A′)|(B-B′)는 아는 값이고 (A|B)-(A′|B′)에서 B, A′은 모르는 값이다. 여기서 (A|B)=a|b|c|d |e|f|g|h이고 (A′|B′)=h|a|b|c|d|e|f|g이다. 즉, (A|B)를 오른쪽으로 8비트 쉬프트 해준 게 (A′|B′)이다. (A|B)-(A′|B′)=x1 x2 x3 x4 x5 x6 x7 x8이라고 하면 이 8비트는 아는 값이다. 그리고 a~h 중 a가 미지수면 x1을 알고 있기 때문에 h를 구할 수 있다. 이 부분에서도 carry발생을 고려해야 하고 맨 앞에서 설정한 h가 뒤에서 설정한 h이면 마스터키 후보가 된다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335915-aa60fe1c-f3c9-43e6-89f9-4cf4cada07b5.png)
	![제목 없음](https://user-images.githubusercontent.com/84726924/197335927-a4c61800-9fd1-4501-8044-20c6f3b44fdd.png)
	+ 마스터 키 후보군을 찾는 구현 코드는 아래와 같다. 마스터키 후보군들은 txt파일로 저장한다.
	```
	void cal_masterkey(void) {
	FILE* f_masterKey;
	ULONG T0[2] = { 0 }, T1[2] = { 0 };

	T0[0] = RK[0][0]; //K1,0
	T1[0] = RK[0][1]; //K1,1
	T0[1] = RK[1][0]; //K2,0
	T1[1] = RK[1][1]; //K2,1
	SEED_G_INV(&T0[0]);
	SEED_G_INV(&T0[1]);
	SEED_G_INV(&T1[0]);
	SEED_G_INV(&T1[1]);

	//SEED 키스케쥴 함수에서 사용되는 라운드 상수
	T0[0] += SEED_KC[0];
	T0[1] += SEED_KC[1];
	T1[0] -= SEED_KC[0];
	T1[1] -= SEED_KC[1];

	ULONG X = 0x89111111; // T0[0] - T0[1]
	ULONG Y = 0x11111111; // T1[0] - T1[1]

	f_masterKey = fopen("C:\\", "wb"); //마스터 키 위치
	if (f_masterKey == NULL) {
		printf("File Open Error4!!\n");
	}
	
	for (int i = 0x0; i <= 0xff; i++) {
		int A[4] = { 0 }, B[4] = { 0 };
		A[0] += i & 0xff;
		A[1] += A[0] - (X & 0xff);
		if (A[1] < 0) {
			A[1] += 0x100;
			A[2]--;
		}
		A[2] += A[1] - ((X >> 8) & 0xff);
		if (A[2] < 0) {
			A[2] += 0x100;
			A[3]--;
		}
		A[3] += A[2] - ((X >> 16) & 0xff);
		if (A[3] < 0) {
			A[3] += 0x100;
			B[0]--;
		}
		B[0] += A[3] - ((X >> 24) & 0xff);
		if (B[0] < 0) {
			B[0] += 0x100;
		}
		B[1] += B[0] - (Y & 0xff);
		if (B[1] < 0) {
			B[1] += 0x100;
			B[2]--;
		}
		B[2] += B[1] - ((Y >> 8) & 0xff);
		if (B[2] < 0) {
			B[2] += 0x100;
			B[3]--;
		}
		B[3] += B[2] - ((Y >> 16) & 0xff);
		if (B[3] < 0) {
			B[3] += 0x100;
		}

		UCHAR AA[4], BB[4];
		for (int j = 0; j < 4; j++) {
			AA[3 - j] = (UCHAR)A[j];
			BB[3 - j] = (UCHAR)B[j];
		}

		ULONG AAA = out_32bit(&AA[0]);
		ULONG BBB = out_32bit(&BB[0]);
		ULONG C = T0[0] - AAA;
		ULONG D = BBB - T1[0];

		if (AAA + C != T0[0] || BBB - D != T1[0]) {
			continue;
		}

		TwoWordRRot(AAA, BBB);

		if (AAA + C != T0[1] || BBB - D != T1[1]) {
			continue;
		}

		TwoWordLRot(AAA, BBB);
		//printf("Master Key : %08X%08X%08X%08X\n", AAA, BBB, C, D);
		fprintf(f_masterKey, "%08X%08X%08X%08X\n", AAA, BBB, C, D);
	}
	fclose(f_masterKey);
	}
	```
	+ Inv_G함수 구현은 아래와 같다. 이 부분은 SEED G의 역함수를 참고하여 구현하면 된다.
	```
	void SEED_G_INV(ULONG* S) {
	UCHAR Z[4];
	Z[0] = ((*S) >> 0) & 0xFF;
	Z[1] = ((*S) >> 8) & 0xFF;
	Z[2] = ((*S) >> 16) & 0xFF;
	Z[3] = ((*S) >> 24) & 0xFF;

	UCHAR U[4];
	U[0] = Z[0] ^ Z[1] ^ Z[2];
	U[1] = Z[0] ^ Z[1] ^ Z[3];
	U[2] = Z[0] ^ Z[2] ^ Z[3];
	U[3] = Z[1] ^ Z[2] ^ Z[3];

	UCHAR Y[4];
	Y[0] = SEED_S1box_inv[(U[0] & 0xC0) ^ (U[1] & 0x30) ^ (U[2] & 0x0C) ^ (U[3] & 0x03)];
	Y[1] = SEED_S2box_inv[(U[0] & 0x03) ^ (U[1] & 0xC0) ^ (U[2] & 0x30) ^ (U[3] & 0x0C)];
	Y[2] = SEED_S1box_inv[(U[0] & 0x0C) ^ (U[1] & 0x03) ^ (U[2] & 0xC0) ^ (U[3] & 0x30)];
	Y[3] = SEED_S2box_inv[(U[0] & 0x30) ^ (U[1] & 0x0C) ^ (U[2] & 0x03) ^ (U[3] & 0xC0)];

	ULONG X = Y[3];
	X = X << 8;
	X += Y[2];
	X = X << 8;
	X += Y[1];
	X = X << 8;
	X += Y[0];

	(*S) = X;
	}
	```
	+ 마스터 키 후보군들이다. 총 150개가 조금 넘는다. 여기서 마스터 키는 00,11,22,33,44,55,66, 77,88,99,AA,BB,CC,DD,EE,FF이다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197336062-91524a6c-be5e-4180-bb60-68f91be2d6f8.png)
+ **암호문 복호화**
	+ CPA로 구한 마스터 키와 암호문을 복호화하면 평문을 얻을 수 있다.
	
	![제목 없음](https://user-images.githubusercontent.com/84726924/197336099-c2ea136c-a2f5-4adc-a035-2167756aef17.png)
	+ 복호화 하여 얻은 16진수 평문을 유니코드(UTF-8) 한글 코드표를 참고하여 변환하면 된다.
