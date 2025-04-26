package com.springSecurity.spring.security.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;


public class DataSourceConfig {

    @Autowired
    private DataSource dataSource;


    public DataSourceInitializer dataSourceInitializer (){
        DataSourceInitializer dataSourceInitializer = new DataSourceInitializer();
        dataSourceInitializer.setDataSource(dataSource);

        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("schema.sql"));
        dataSourceInitializer.setDatabasePopulator(populator);

        return dataSourceInitializer;
    }
}
