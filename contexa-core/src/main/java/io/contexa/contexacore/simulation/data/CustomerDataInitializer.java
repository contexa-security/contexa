package io.contexa.contexacore.simulation.data;

import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.repository.CustomerDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 고객 데이터 초기화
 *
 * 테스트용 고객 데이터를 생성합니다.
 * 실제 운영 환경에서는 실행되지 않도록 @Profile("simulation")을 사용합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
@Profile("simulation")
@RequiredArgsConstructor
public class CustomerDataInitializer implements CommandLineRunner {

    private final CustomerDataRepository customerDataRepository;

    private static final String[] FIRST_NAMES = {
        "김", "이", "박", "최", "정", "강", "조", "윤", "장", "임",
        "한", "오", "서", "신", "권", "황", "안", "송", "류", "전"
    };

    private static final String[] LAST_NAMES = {
        "민준", "서준", "도윤", "예준", "시우", "하준", "주원", "지호", "지후", "준우",
        "서연", "서윤", "지우", "서현", "지윤", "수아", "하윤", "지아", "하은", "윤서"
    };

    private static final String[] CITIES = {
        "서울", "부산", "대구", "인천", "광주", "대전", "울산", "세종", "경기", "강원"
    };

    private static final String[] DOMAINS = {
        "example.com", "test.com", "demo.com", "sample.org", "mail.com"
    };

    @Override
    public void run(String... args) throws Exception {
        // 이미 데이터가 있는지 확인
        long count = customerDataRepository.count();

        if (count > 0) {
            log.info("Customer data already exists: {} records", count);
            return;
        }

        log.info("Initializing customer test data...");

        List<CustomerData> customers = generateCustomerData(1000);
        customerDataRepository.saveAll(customers);

        log.info("Created {} customer records for simulation testing", customers.size());
    }

    /**
     * 테스트용 고객 데이터 생성
     */
    private List<CustomerData> generateCustomerData(int count) {
        List<CustomerData> customers = new ArrayList<>();
        Random random = new Random();

        for (int i = 1; i <= count; i++) {
            CustomerData customer = new CustomerData();

            // 고객 ID
            customer.setCustomerId("customer-" + i);

            // 이름
            String firstName = FIRST_NAMES[random.nextInt(FIRST_NAMES.length)];
            String lastName = LAST_NAMES[random.nextInt(LAST_NAMES.length)];
            customer.setName(firstName + lastName);

            // 이메일
            String email = lastName.toLowerCase() + i + "@" + DOMAINS[random.nextInt(DOMAINS.length)];
            customer.setEmail(email);

            // 전화번호
            customer.setPhoneNumber(String.format("010-%04d-%04d",
                random.nextInt(10000), random.nextInt(10000)));

            // 주소
            String city = CITIES[random.nextInt(CITIES.length)];
            customer.setAddress(city + "시 " + (random.nextInt(100) + 1) + "번지");

            // 신용카드 번호 (마스킹된 형태)
            customer.setCreditCardNumber(String.format("****-****-****-%04d",
                random.nextInt(10000)));

            // 주민등록번호 (마스킹된 형태)
            int year = 1950 + random.nextInt(50);
            int month = random.nextInt(12) + 1;
            int day = random.nextInt(28) + 1;
            customer.setSocialSecurityNumber(String.format("%02d%02d%02d-*******",
                year % 100, month, day));

            // 계좌 잔액
            customer.setAccountBalance(random.nextDouble() * 10000000);

            // 회원 등급
            CustomerData.MembershipTier[] tiers = CustomerData.MembershipTier.values();
            customer.setMembershipTier(tiers[random.nextInt(tiers.length)]);

            // 민감도 레벨 설정
            CustomerData.SensitivityLevel sensitivityLevel;
            if (i <= 50) {
                // 상위 5%는 CRITICAL
                sensitivityLevel = CustomerData.SensitivityLevel.CRITICAL;
            } else if (i <= 200) {
                // 다음 15%는 HIGH
                sensitivityLevel = CustomerData.SensitivityLevel.HIGH;
            } else if (i <= 500) {
                // 다음 30%는 MEDIUM
                sensitivityLevel = CustomerData.SensitivityLevel.MEDIUM;
            } else {
                // 나머지 50%는 LOW
                sensitivityLevel = CustomerData.SensitivityLevel.LOW;
            }
            customer.setSensitivityLevel(sensitivityLevel);

            // 마지막 로그인
            customer.setLastLogin(LocalDate.now().minusDays(random.nextInt(365)).atStartOfDay());

            // 가입일
            customer.setCreatedDate(LocalDate.now().minusDays(random.nextInt(1825)).atStartOfDay()); // 5년 내

            // 활성 상태
            customer.setActive(random.nextDouble() > 0.1); // 90% 활성

            // 2FA 활성화
            customer.setTwoFactorEnabled(random.nextDouble() > 0.3); // 70% 2FA 사용

            // 개인정보 (JSON 형태의 추가 정보)
            customer.setPersonalInfo(generatePersonalInfo(random));

            customers.add(customer);
        }

        return customers;
    }

    /**
     * 추가 개인정보 생성
     */
    private String generatePersonalInfo(Random random) {
        StringBuilder info = new StringBuilder();
        info.append("{");

        // 나이
        info.append("\"age\": ").append(20 + random.nextInt(50)).append(", ");

        // 성별
        info.append("\"gender\": \"").append(random.nextBoolean() ? "M" : "F").append("\", ");

        // 직업
        String[] jobs = {"회사원", "자영업", "전문직", "학생", "주부", "프리랜서", "공무원", "기타"};
        info.append("\"occupation\": \"").append(jobs[random.nextInt(jobs.length)]).append("\", ");

        // 연소득 (백만원 단위)
        info.append("\"annualIncome\": ").append(20 + random.nextInt(180)).append(", ");

        // VIP 여부
        info.append("\"isVIP\": ").append(random.nextDouble() > 0.9).append(", ");

        // 신용등급
        info.append("\"creditScore\": ").append(300 + random.nextInt(550)).append(", ");

        // 선호 언어
        String[] languages = {"ko", "en", "zh", "ja"};
        info.append("\"preferredLanguage\": \"").append(languages[random.nextInt(languages.length)]).append("\", ");

        // 마케팅 동의
        info.append("\"marketingConsent\": ").append(random.nextBoolean()).append(", ");

        // 최근 거래 횟수
        info.append("\"recentTransactionCount\": ").append(random.nextInt(100)).append(", ");

        // 보안 질문
        info.append("\"securityQuestion\": \"").append("출신 초등학교는?").append("\"");

        info.append("}");

        return info.toString();
    }

    /**
     * 특정 민감도의 VIP 고객 생성
     */
    public CustomerData createVIPCustomer(String customerId, CustomerData.SensitivityLevel sensitivity) {
        CustomerData vip = new CustomerData();

        vip.setCustomerId(customerId);
        vip.setName("VIP 고객");
        vip.setEmail("vip@example.com");
        vip.setPhoneNumber("010-0000-0000");
        vip.setAddress("서울시 강남구");
        vip.setCreditCardNumber("****-****-****-9999");
        vip.setSocialSecurityNumber("900101-*******");
        vip.setAccountBalance(1000000000.0); // 10억
        vip.setMembershipTier(CustomerData.MembershipTier.PLATINUM);
        vip.setSensitivityLevel(sensitivity);
        vip.setLastLogin(LocalDate.now().atStartOfDay());
        vip.setCreatedDate(LocalDate.now().minusYears(5).atStartOfDay());
        vip.setActive(true);
        vip.setTwoFactorEnabled(true);
        vip.setPersonalInfo("{\"isVIP\": true, \"creditScore\": 850}");

        return vip;
    }

    /**
     * 테스트용 타겟 고객 생성
     */
    public List<CustomerData> createTargetCustomers() {
        List<CustomerData> targets = new ArrayList<>();

        // 각 민감도별로 타겟 생성
        targets.add(createVIPCustomer("target-critical-1", CustomerData.SensitivityLevel.CRITICAL));
        targets.add(createVIPCustomer("target-critical-2", CustomerData.SensitivityLevel.CRITICAL));
        targets.add(createVIPCustomer("target-high-1", CustomerData.SensitivityLevel.HIGH));
        targets.add(createVIPCustomer("target-high-2", CustomerData.SensitivityLevel.HIGH));
        targets.add(createVIPCustomer("target-medium-1", CustomerData.SensitivityLevel.MEDIUM));
        targets.add(createVIPCustomer("target-low-1", CustomerData.SensitivityLevel.LOW));

        return targets;
    }
}