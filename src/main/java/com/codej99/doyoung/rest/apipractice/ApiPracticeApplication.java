package com.codej99.doyoung.rest.apipractice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.EventListener;

@SpringBootApplication
public class ApiPracticeApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext ac = SpringApplication.run(ApiPracticeApplication.class, args);
//        ac.addApplicationListener(new ApplicationListener<MyEvent>() {
//            @Override
//            public void onApplicationEvent(MyEvent event) {
//                System.out.println("Hello applicationEvent : " + event.getMessage());
//            }
//        });

        ac.publishEvent(new MyEvent(ac, "My Spring Event"));
    }

    @EventListener(MyEvent.class)
    public void init(MyEvent myEvent) {
        System.out.println("custom Hello applicationEvent :: " + myEvent.getMessage());
    }

    static class MyEvent extends ApplicationEvent {
        private final String message; //원래 String message는 없는 건데 추가한 것임.

        public MyEvent(Object source, String message) {
            super(source);
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }


}
