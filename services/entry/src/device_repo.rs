use domain::Device;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresDeviceRepository {
    pool: PgPool,
}

impl PostgresDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn count_devices(&self, customer_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM devices WHERE customer_id = $1")
            .bind(customer_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn register_device(&self, device: &Device) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO devices (id, customer_id, name, public_key, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(device.id)
        .bind(device.customer_id)
        .bind(&device.name)
        .bind(&device.public_key)
        .bind(device.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_devices(&self, customer_id: Uuid) -> Result<Vec<Device>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DeviceDbRow>(
            "SELECT id, customer_id, name, public_key, created_at
             FROM devices
             WHERE customer_id = $1
             ORDER BY created_at ASC",
        )
        .bind(customer_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get_device(
        &self,
        customer_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<Device>, sqlx::Error> {
        let row = sqlx::query_as::<_, DeviceDbRow>(
            "SELECT id, customer_id, name, public_key, created_at
             FROM devices
             WHERE customer_id = $1 AND id = $2
             LIMIT 1",
        )
        .bind(customer_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }
}

#[derive(sqlx::FromRow)]
struct DeviceDbRow {
    id: Uuid,
    customer_id: Uuid,
    name: String,
    public_key: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<DeviceDbRow> for Device {
    fn from(value: DeviceDbRow) -> Self {
        Self {
            id: value.id,
            customer_id: value.customer_id,
            name: value.name,
            public_key: value.public_key,
            created_at: value.created_at,
        }
    }
}
