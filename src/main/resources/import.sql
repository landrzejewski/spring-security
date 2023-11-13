create table users(username varchar(50) not null primary key, password varchar(100) not null, enabled boolean not null);
create table authorities (username varchar(50) not null, authority varchar(50) not null);

insert into users (username, password, enabled) values ('admin', 'admin', 1);
insert into authorities (username, authority) values ('admin', 'ROLE_ADMIN');
