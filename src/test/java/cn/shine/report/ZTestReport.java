package cn.shine.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.testng.*;
import org.testng.xml.XmlSuite;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;

/**
 * ZTestReport
 * <p>
 * <a href="https://github.com/shenyanf/junitHtmlReport">https://github.com/shenyanf/junitHtmlReport</a>
 *
 * @author shenyf
 */
public class ZTestReport implements IReporter {
    /**
     * path: report html path
     */
    private final String path = System.getProperty("user.dir") + File.separator + "src/test/resources/report.html";
    /**
     * templatePath: template path
     */
    private final String templatePath = System.getProperty("user.dir") + File.separator + "src/test/resources/template";
    /**
     * testsPass: tests pass
     */
    private int testsPass = 0;
    /**
     * testsFail: tests fail
     */
    private int testsFail = 0;
    /**
     * testsSkip: tests skip
     */
    private int testsSkip = 0;
    /**
     * beginTime: begin time
     */
    private String beginTime;
    /**
     * totalTime: total time
     */
    private long totalTime;
    /**
     * name: test name
     */
    private String name;

    /**
     * ZTestReport init
     */
    public ZTestReport() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssSSS");
        name = formatter.format(System.currentTimeMillis());
    }

    /**
     * ZTestReport init
     *
     * @param name test name
     */
    public ZTestReport(String name) {
        this.name = name;
        if (this.name == null) {
            SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssSSS");
            this.name = formatter.format(System.currentTimeMillis());
        }
    }

    /**
     * generate report
     *
     * @param xmlSuites       null
     * @param suites          null
     * @param outputDirectory null
     */
    @Override
    public void generateReport(List<XmlSuite> xmlSuites, @NotNull List<ISuite> suites, String outputDirectory) {
        List<ITestResult> list = new ArrayList<>();
        for (ISuite suite : suites) {
            Map<String, ISuiteResult> suiteResults = suite.getResults();
            for (ISuiteResult suiteResult : suiteResults.values()) {
                ITestContext testContext = suiteResult.getTestContext();
                IResultMap passedTests = testContext.getPassedTests();
                testsPass = testsPass + passedTests.size();
                IResultMap failedTests = testContext.getFailedTests();
                testsFail = testsFail + failedTests.size();
                IResultMap skippedTests = testContext.getSkippedTests();
                testsSkip = testsSkip + skippedTests.size();
                IResultMap failedConfig = testContext.getFailedConfigurations();
                list.addAll(this.listTestResult(passedTests));
                list.addAll(this.listTestResult(failedTests));
                list.addAll(this.listTestResult(skippedTests));
                list.addAll(this.listTestResult(failedConfig));
            }
        }
        this.sort(list);
        this.outputResult(list);
    }

    /**
     * list test result
     *
     * @param resultMap null
     * @return ArrayList
     */
    private @NotNull ArrayList<ITestResult> listTestResult(@NotNull IResultMap resultMap) {
        Set<ITestResult> results = resultMap.getAllResults();
        return new ArrayList<>(results);
    }

    /**
     * sort
     *
     * @param list null
     */
    private void sort(@NotNull List<ITestResult> list) {
        list.sort((r1, r2) -> {
            if (r1.getStartMillis() > r2.getStartMillis()) {
                return 1;
            } else {
                return -1;
            }
        });
    }

    /**
     * output result
     *
     * @param list null
     */
    private void outputResult(@NotNull List<ITestResult> list) {
        try {
            List<ReportInfo> listInfo = new ArrayList<>();
            int index = 0;
            for (ITestResult result : list) {
                String tn = result.getTestContext().getCurrentXmlTest().getParameter("testCase");
                if (index == 0) {
                    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
                    beginTime = formatter.format(new Date(result.getStartMillis()));
                    index++;
                }
                long spendTime = result.getEndMillis() - result.getStartMillis();
                totalTime += spendTime;
                String status = this.getStatus(result.getStatus());
                List<String> log = Reporter.getOutput(result);
                log.replaceAll(this::toHtml);
                Throwable throwable = result.getThrowable();
                if (throwable != null) {
                    log.add(this.toHtml(throwable.toString()));
                    StackTraceElement[] st = throwable.getStackTrace();
                    for (StackTraceElement stackTraceElement : st) {
                        log.add(this.toHtml("    " + stackTraceElement));
                    }
                }
                ReportInfo info = new ReportInfo();
                info.setName(tn);
                info.setSpendTime(spendTime + "ms");
                info.setStatus(status);
                info.setClassName(result.getInstanceName());
                info.setMethodName(result.getName());
                info.setDescription(result.getMethod().getDescription());
                info.setLog(log);
                listInfo.add(info);
            }
            Map<String, Object> result = new HashMap<>();
            result.put("testName", name);
            result.put("testPass", testsPass);
            result.put("testFail", testsFail);
            result.put("testSkip", testsSkip);
            result.put("testAll", testsPass + testsFail + testsSkip);
            result.put("beginTime", beginTime);
            result.put("totalTime", totalTime + "ms");
            result.put("testResult", listInfo);
            Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
            String template = this.read(templatePath);
            BufferedWriter output = new BufferedWriter(new OutputStreamWriter(Files.newOutputStream(new File(path).toPath()), StandardCharsets.UTF_8));
            assert template != null;
            template = template.replaceFirst("\\$\\{resultData\\}", Matcher.quoteReplacement(gson.toJson(result)));
            output.write(template);
            output.flush();
            output.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * get status
     *
     * @param status null
     * @return String
     */
    private String getStatus(int status) {
        String statusString = null;
        switch (status) {
            case 1:
                statusString = "Success";
                break;
            case 2:
                statusString = "Failed";
                break;
            case 3:
                statusString = "Pass";
                break;
            default:
                break;
        }
        return statusString;
    }

    /**
     * to html
     *
     * @param str null
     * @return String
     */
    private @NotNull String toHtml(String str) {
        if (str == null) {
            return "";
        } else {
            str = str.replaceAll("<", "&lt;");
            str = str.replaceAll(">", "&gt;");
            str = str.replaceAll(" ", "&nbsp;");
            str = str.replaceAll("\n", "<br>");
            str = str.replaceAll("\"", "\\\\\"");
        }
        return str;
    }

    /**
     * Class Report Info
     */
    public static class ReportInfo {
        /**
         * params
         */
        private String name, className, methodName, description, spendTime, status;
        /**
         * log
         */
        private List<String> log;

        /**
         * get name
         *
         * @return String
         */
        public String getName() {
            return name;
        }

        /**
         * set name
         *
         * @param name null
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * get class name
         *
         * @return String
         */
        public String getClassName() {
            return className;
        }

        /**
         * set class name
         *
         * @param className null
         */
        public void setClassName(String className) {
            this.className = className;
        }

        /**
         * get method name
         *
         * @return String
         */
        public String getMethodName() {
            return methodName;
        }

        /**
         * set method name
         *
         * @param methodName null
         */
        public void setMethodName(String methodName) {
            this.methodName = methodName;
        }

        /**
         * get spend time
         *
         * @return String
         */
        public String getSpendTime() {
            return spendTime;
        }

        /**
         * set spend time
         *
         * @param spendTime null
         */
        public void setSpendTime(String spendTime) {
            this.spendTime = spendTime;
        }

        /**
         * get status
         *
         * @return String
         */
        public String getStatus() {
            return status;
        }

        /**
         * set status
         *
         * @param status null
         */
        public void setStatus(String status) {
            this.status = status;
        }

        /**
         * get log
         *
         * @return List
         */
        public List<String> getLog() {
            return log;
        }

        /**
         * set log
         *
         * @param log null
         */
        public void setLog(List<String> log) {
            this.log = log;
        }

        /**
         * get description
         *
         * @return String
         */
        public String getDescription() {
            return description;
        }

        /**
         * set description
         *
         * @param description null
         */
        public void setDescription(String description) {
            this.description = description;
        }

    }

    /**
     * read file
     *
     * @param path null
     * @return String
     */
    private @Nullable String read(String path) {
        File file = new File(path);
        InputStream is = null;
        StringBuilder sb = new StringBuilder();
        try {
            is = Files.newInputStream(file.toPath());
            int index;
            byte[] b = new byte[1024];
            while ((index = is.read(b)) != -1) {
                sb.append(new String(b, 0, index));
            }
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
}
