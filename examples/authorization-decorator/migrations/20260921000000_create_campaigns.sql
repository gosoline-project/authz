-- +goose Up
-- +goose StatementBegin
create table stored_campaigns
(
    id            int auto_increment primary key,
    business_unit varchar(255) not null,
    name          varchar(255) not null,
    updated_at    timestamp null,
    created_at    timestamp null
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table stored_campaigns;
-- +goose StatementEnd
