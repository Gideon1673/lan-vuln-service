from app.common.config import RabbitMQConfig
from app.common.messaging.event import BaseEvent
from app.common.messaging.event_keys import EventKeys
from app.common.messaging.rabbitmq import RabbitEventBus

bus = RabbitEventBus(RabbitMQConfig.from_env())
