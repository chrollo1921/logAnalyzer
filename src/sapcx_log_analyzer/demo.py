"""Generate a realistic, entirely synthetic SAP Commerce Cloud log export.

The export looks like a Dynatrace Grail ``fetch logs`` download of a CCv2 environment:
Tomcat access log lines and log4j2 JSON application lines from the ``api`` pods, with
OneAgent trace ids and project MDC values (user id, B2B account id, session id), plus
background processing and Backoffice noise. Several incidents are planted so there is
something to ask about:

- user ``23dsfd`` cannot place an order because the payment provider times out,
- ``GET /occ/v2/electronics/cart/323232/getDelivery`` fails because the carrier API times out,
- B2B account ``1234`` has a user whose order needs approval and who hits a missing permission,
- a database connection pool outage breaks random requests for a few minutes,
- a Solr indexing CronJob fails and a long GC pause is logged.

All names, ids, emails and addresses are invented. Use it to try the tool without real data.
"""

from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

T0 = datetime(2026, 10, 20, 8, 0, 0, tzinfo=UTC)
SITE = "electronics"
API_PODS = ["api-7d9f8c6b5-abcde", "api-7d9f8c6b5-fghij", "api-7d9f8c6b5-klmno"]
BG_POD = "backgroundprocessing-5c6b7d8e9-pqrst"
BO_POD = "backoffice-6f7a8b9c0-uvwxy"
OUTAGE = (T0 + timedelta(minutes=50), T0 + timedelta(minutes=57))

CART_FACADE = "de.hybris.platform.commercefacades.order.impl.DefaultCartFacade"
CHECKOUT_FACADE = "de.hybris.platform.commercefacades.order.impl.DefaultCheckoutFacade"
PLACE_ORDER = "de.hybris.platform.commerceservices.order.impl.DefaultCommerceCheckoutService"
DELIVERY_CTRL = "com.example.occ.controllers.DeliveryController"
CARRIER_CLIENT = "com.example.delivery.client.CarrierRateClient"
PAYMENT_ACTION = "com.example.payment.PspAuthorizationService"
ERROR_HANDLER = "de.hybris.platform.webservicescommons.handler.DefaultWebserviceErrorHandler"
PRODUCT_FACADE = "de.hybris.platform.commercefacades.product.impl.DefaultProductFacade"
B2B_APPROVAL = "de.hybris.platform.b2b.process.approval.actions.B2BPermissionResultHelper"
OAUTH_ENDPOINT = "de.hybris.platform.oauth2.controller.OAuth2TokenEndpoint"
LOGIN_AUDIT = "com.example.occ.security.LoginAuditListener"
INDEXER_EXCEPTION = "de.hybris.platform.solrfacetsearch.indexer.exceptions.IndexerException"

HIKARI_ERROR = {
    "name": "org.springframework.jdbc.CannotGetJdbcConnectionException",
    "message": "Failed to obtain JDBC Connection",
    "extendedStackTrace": [
        {
            "class": "org.springframework.jdbc.datasource.DataSourceUtils",
            "method": "getConnection",
            "file": "DataSourceUtils.java",
            "line": 84,
        },
        {
            "class": "de.hybris.platform.jdbcwrapper.HybrisDataSource",
            "method": "getConnection",
            "file": "HybrisDataSource.java",
            "line": 120,
        },
    ],
    "cause": {
        "name": "java.sql.SQLTransientConnectionException",
        "message": "HikariPool-1 - Connection is not available, request timed out after 30000ms.",
    },
}


@dataclass
class Customer:
    customer_id: str
    email: str
    account_id: str | None = None
    sessions: list[str] = field(default_factory=list)


@dataclass
class _Writer:
    rng: random.Random
    records: list[dict[str, Any]] = field(default_factory=list)
    size: int = 0

    def add(
        self,
        when: datetime,
        level: str,
        pod: str,
        content: str,
        trace: str | None = None,
        span: str | None = None,
        container: str = "platform",
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "loglevel": level,
            "content": content,
            "k8s.namespace.name": "s1a2b3c4d5-p1",
            "k8s.pod.name": pod,
            "k8s.container.name": container,
            "dt.entity.cloud_application": "CLOUD_APPLICATION-1234ABCD",
        }
        if trace:
            record["trace_id"] = trace
            record["span_id"] = span or self.hex(16)
        self.records.append(record)
        self.size += len(json.dumps(record)) + 2

    def hex(self, length: int) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(length))


def _app_line(
    when: datetime,
    level: str,
    thread: str,
    logger: str,
    message: str,
    context: dict[str, str] | None = None,
    thrown: dict[str, Any] | None = None,
) -> str:
    doc: dict[str, Any] = {
        "instant": {"epochSecond": int(when.timestamp()), "nanoOfSecond": when.microsecond * 1000},
        "thread": thread,
        "level": level,
        "loggerName": logger,
        "message": message,
        "endOfBatch": False,
        "loggerFqcn": "org.apache.logging.log4j.spi.AbstractLogger",
    }
    if context:
        doc["contextMap"] = context
    if thrown:
        doc["thrown"] = thrown
    return json.dumps(doc)


def _access_line(when: datetime, ip: str, method: str, path: str, status: int, ms: int) -> str:
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.Random(path).randint(200, 9000) if status < 400 else 180
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} {ms}ms'


class _Generator:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.out = _Writer(self.rng)
        self.customers = self._customers()

    # --- people ------------------------------------------------------------------------

    def _customers(self) -> list[Customer]:
        first = ["anna", "ben", "chen", "dara", "eli", "fatima", "gus", "hana", "ivan", "jo"]
        last = ["meyer", "khan", "silva", "novak", "ito", "larsen", "okafor", "ruiz", "berg"]
        customers = [
            Customer("23dsfd", "priya.raman@example.com"),
            Customer("88kq2m", "tom.becker@example.org"),
            Customer("b2b7x1", "alex.morgan@acme-corp.example", account_id="1234"),
            Customer("b2b7x2", "sam.lee@acme-corp.example", account_id="1234"),
        ]
        for _ in range(400):
            code = "".join(
                self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(6)
            )
            name = f"{self.rng.choice(first)}.{self.rng.choice(last)}{self.rng.randint(1, 99)}"
            email = f"{name}@example.net"
            account = str(self.rng.randint(2000, 2100)) if self.rng.random() < 0.15 else None
            customers.append(Customer(code, email, account_id=account))
        for customer in customers:
            customer.sessions = [
                "".join(self.rng.choice("0123456789ABCDEF") for _ in range(32))
                for _ in range(self.rng.randint(1, 2))
            ]
        return customers

    # --- one OCC request -------------------------------------------------------------

    def request(
        self,
        when: datetime,
        customer: Customer | None,
        session: str | None,
        method: str,
        path: str,
        handler: str,
        message: str,
        status: int = 200,
        ms: int | None = None,
        failure: tuple[str, str, dict[str, Any] | None] | None = None,
        extra: list[tuple[str, str, str]] | None = None,
    ) -> datetime:
        """Write the app lines and the access log line of one request; return its end."""
        rng = self.rng
        pod = rng.choice(API_PODS)
        thread = f"hybrisHTTP{rng.randint(1, 64)}"
        trace = self.out.hex(32)
        ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        context: dict[str, str] = {
            "CorrelationId": _uuid(rng),
            "RemoteAddr": ip,
            "Tenant": "master",
        }
        if customer is not None:
            context["userId"] = customer.customer_id
            if customer.account_id:
                context["b2bUnitId"] = customer.account_id
        if session is not None:
            context["sessionId"] = session
        in_outage = OUTAGE[0] <= when <= OUTAGE[1] and failure is None and rng.random() < 0.35
        if in_outage:
            status, failure = 500, ("ERROR", "Could not handle request", HIKARI_ERROR)
        duration = ms if ms is not None else (30_000 if in_outage else rng.randint(15, 400))

        t = when
        self.out.add(
            t, "DEBUG", pod, _app_line(t, "DEBUG", thread, handler, message, context), trace
        )
        for level, logger, text in extra or []:
            t += timedelta(milliseconds=rng.randint(5, 60))
            self.out.add(t, level, pod, _app_line(t, level, thread, logger, text, context), trace)
        end = when + timedelta(milliseconds=duration)
        if failure is not None:
            level, text, thrown = failure
            self.out.add(
                end,
                level,
                pod,
                _app_line(
                    end,
                    level,
                    thread,
                    PLACE_ORDER if thrown is HIKARI_ERROR else handler,
                    text,
                    context,
                    thrown,
                ),
                trace,
            )
            if status >= 500:
                note = f"Request {method} {path} failed with {status}"
                self.out.add(
                    end,
                    "WARN",
                    pod,
                    _app_line(end, "WARN", thread, ERROR_HANDLER, note, context),
                    trace,
                )
        self.out.add(
            end,
            "INFO",
            pod,
            _access_line(end, ip, method, path, status, duration),
            trace,
            container="access-log",
        )
        return end

    # --- journeys ----------------------------------------------------------------------

    def login(self, when: datetime, customer: Customer, session: str) -> datetime:
        """The OAuth password grant that starts a visit, the line that ties email to user id."""
        end = self.request(
            when,
            customer,
            session,
            "POST",
            "/authorizationserver/oauth/token",
            OAUTH_ENDPOINT,
            "Issuing access token for grant_type=password",
            extra=[
                (
                    "INFO",
                    LOGIN_AUDIT,
                    f"Customer {customer.email} logged in, customerId {customer.customer_id}",
                )
            ],
        )
        return end + timedelta(seconds=self.rng.randint(1, 5))

    def shopping_journey(self, start: datetime, customer: Customer, session: str) -> None:
        rng = self.rng
        uid = rng.choice(["current", customer.email])
        cart = f"{rng.randint(100000, 999999)}"
        base = f"/occ/v2/{SITE}/users/{uid}/carts/{cart}"
        t = self.login(start, customer, session)
        for _ in range(rng.randint(1, 4)):
            code = str(rng.randint(1000000, 9999999))
            t = self.request(
                t,
                customer,
                session,
                "GET",
                f"/occ/v2/{SITE}/products/{code}",
                PRODUCT_FACADE,
                f"Loading product {code}",
            )
            t += timedelta(seconds=rng.randint(3, 40))
        t = self.request(
            t,
            customer,
            session,
            "POST",
            f"{base}/entries",
            CART_FACADE,
            f"Adding entry to cart {cart}",
        )
        if rng.random() < 0.5:
            return
        t += timedelta(seconds=rng.randint(5, 60))
        t = self.request(
            t,
            customer,
            session,
            "GET",
            f"/occ/v2/{SITE}/cart/{cart}/getDelivery",
            DELIVERY_CTRL,
            f"Fetching delivery options for cart {cart}",
            extra=[("DEBUG", CARRIER_CLIENT, f"Carrier rate request for cart {cart} -> 200")],
        )
        t += timedelta(seconds=rng.randint(5, 30))
        t = self.request(
            t,
            customer,
            session,
            "PUT",
            f"{base}/deliverymode?deliveryModeId=standard-net",
            CHECKOUT_FACADE,
            f"Setting delivery mode standard-net on cart {cart}",
        )
        t += timedelta(seconds=rng.randint(10, 90))
        t = self.request(
            t,
            customer,
            session,
            "POST",
            f"{base}/paymentdetails",
            CHECKOUT_FACADE,
            f"Adding payment details to cart {cart}",
            extra=[("INFO", PAYMENT_ACTION, f"PSP authorization approved for cart {cart}")],
        )
        t += timedelta(seconds=rng.randint(3, 20))
        order = f"{rng.randint(10000000, 99999999)}"
        self.request(
            t,
            customer,
            session,
            "POST",
            f"/occ/v2/{SITE}/users/{uid}/orders?cartId={cart}",
            CHECKOUT_FACADE,
            f"Placing order for cart {cart}",
            status=201,
            extra=[("INFO", PLACE_ORDER, f"Order {order} placed for cart {cart}")],
        )

    def failed_payment(self, start: datetime) -> None:
        """User 23dsfd: payment authorization times out, so the order cannot be placed."""
        customer = self.customers[0]
        session = customer.sessions[0]
        cart = "551177"
        base = f"/occ/v2/{SITE}/users/current/carts/{cart}"
        t = self.request(
            self.login(start, customer, session),
            customer,
            session,
            "POST",
            f"{base}/entries",
            CART_FACADE,
            f"Adding entry to cart {cart}",
        )
        t = self.request(
            t + timedelta(seconds=40),
            customer,
            session,
            "PUT",
            f"{base}/deliverymode?deliveryModeId=express",
            CHECKOUT_FACADE,
            f"Setting delivery mode express on cart {cart}",
        )
        for attempt in (1, 2):
            t = self.request(
                t + timedelta(seconds=35),
                customer,
                session,
                "POST",
                f"{base}/paymentdetails",
                CHECKOUT_FACADE,
                f"Adding payment details to cart {cart} (attempt {attempt})",
                status=502,
                ms=20_000,
                extra=[
                    (
                        "WARN",
                        PAYMENT_ACTION,
                        f"PSP authorization for cart {cart} took longer than 15000 ms, retrying",
                    )
                ],
                failure=(
                    "ERROR",
                    f"Payment authorization failed for cart {cart}",
                    {
                        "name": "com.example.payment.PspException",
                        "message": "Authorization request to psp.example-pay.com failed",
                        "extendedStackTrace": [
                            {
                                "class": "com.example.payment.PspAuthorizationService",
                                "method": "authorize",
                                "file": "PspAuthorizationService.java",
                                "line": 88,
                            },
                        ],
                        "cause": {
                            "name": "java.net.SocketTimeoutException",
                            "message": "Read timed out",
                        },
                    },
                ),
            )
        self.request(
            t + timedelta(seconds=20),
            customer,
            session,
            "POST",
            f"/occ/v2/{SITE}/users/current/orders?cartId={cart}",
            CHECKOUT_FACADE,
            f"Placing order for cart {cart}",
            status=400,
            failure=("WARN", f"Cannot place order for cart {cart}: no authorized payment", None),
        )

    def failed_delivery(self, start: datetime) -> None:
        """Cart 323232: the carrier rate API times out, getDelivery returns 504."""
        customer = self.customers[1]
        session = customer.sessions[0]
        cart = "323232"
        t = self.request(
            self.login(start, customer, session),
            customer,
            session,
            "POST",
            f"/occ/v2/{SITE}/users/current/carts/{cart}/entries",
            CART_FACADE,
            f"Adding entry to cart {cart}",
        )
        for _ in range(3):
            t = self.request(
                t + timedelta(seconds=15),
                customer,
                session,
                "GET",
                f"/occ/v2/{SITE}/cart/{cart}/getDelivery",
                DELIVERY_CTRL,
                f"Fetching delivery options for cart {cart}",
                status=504,
                ms=10_050,
                extra=[
                    (
                        "WARN",
                        CARRIER_CLIENT,
                        f"Carrier rate request for cart {cart} to carrier-api.example.com "
                        "exceeded 10000 ms",
                    )
                ],
                failure=(
                    "ERROR",
                    f"Could not get delivery options for cart {cart}",
                    {
                        "name": "com.example.delivery.DeliveryServiceException",
                        "message": "Carrier rate lookup failed for postal code 80331",
                        "extendedStackTrace": [
                            {
                                "class": "com.example.delivery.client.CarrierRateClient",
                                "method": "fetchRates",
                                "file": "CarrierRateClient.java",
                                "line": 142,
                            },
                            {
                                "class": "com.example.occ.controllers.DeliveryController",
                                "method": "getDelivery",
                                "file": "DeliveryController.java",
                                "line": 57,
                            },
                        ],
                        "cause": {
                            "name": "java.net.SocketTimeoutException",
                            "message": "Read timed out",
                        },
                    },
                ),
            )

    def b2b_account(self, start: datetime) -> None:
        """Account 1234: an order over the approval threshold and a missing permission."""
        alex, sam = self.customers[2], self.customers[3]
        cart = "770011"
        base = f"/occ/v2/powertools/users/current/carts/{cart}"
        t = self.request(
            self.login(start, alex, alex.sessions[0]),
            alex,
            alex.sessions[0],
            "GET",
            "/occ/v2/powertools/products/3881018",
            PRODUCT_FACADE,
            "Loading product 3881018",
        )
        t = self.request(
            t + timedelta(seconds=20),
            alex,
            alex.sessions[0],
            "POST",
            f"{base}/entries",
            CART_FACADE,
            f"Adding entry to cart {cart}",
        )
        t = self.request(
            t + timedelta(seconds=30),
            alex,
            alex.sessions[0],
            "GET",
            "/occ/v2/powertools/costcenters",
            "com.example.occ.controllers.CostCenterController",
            "Listing cost centers",
            status=403,
            failure=(
                "WARN",
                "Access denied: user lacks b2bcustomergroup permission "
                "'viewCostCenters' for unit 1234",
                None,
            ),
        )
        t = self.request(
            t + timedelta(seconds=25),
            alex,
            alex.sessions[0],
            "POST",
            f"/occ/v2/powertools/users/current/orders?cartId={cart}&termsChecked=true",
            CHECKOUT_FACADE,
            f"Placing order for cart {cart}",
            status=201,
            extra=[
                ("INFO", PLACE_ORDER, f"Order 40020011 placed for cart {cart}"),
                (
                    "WARN",
                    B2B_APPROVAL,
                    "Order 40020011 total 18450.00 EUR exceeds the "
                    "B2BOrderThresholdPermission of 10000.00 EUR for unit 1234; sent for approval",
                ),
            ],
        )
        self.shopping_journey(t + timedelta(minutes=12), sam, sam.sessions[0])

    def background(self) -> None:
        rng = self.rng
        for minute in range(0, 120, 15):
            t = T0 + timedelta(minutes=minute, seconds=rng.randint(0, 30))
            job = "update-electronicsIndex-cronJob"
            thread = f"{job}::de.hybris.platform.servicelayer.internal.jalo.ServicelayerJob"
            self.out.add(
                t,
                "INFO",
                BG_POD,
                _app_line(
                    t,
                    "INFO",
                    thread,
                    "de.hybris.platform.cronjob.jalo.CronJob",
                    f"Starting CronJob {job}",
                ),
            )
            end = t + timedelta(seconds=rng.randint(20, 90))
            if minute == 45:
                self.out.add(
                    end,
                    "ERROR",
                    BG_POD,
                    _app_line(
                        end,
                        "ERROR",
                        thread,
                        "de.hybris.platform.solrfacetsearch.indexer.impl.DefaultIndexerService",
                        "Error while indexing electronicsIndex",
                        thrown={
                            "name": INDEXER_EXCEPTION,
                            "message": "indexer operation failed",
                            "cause": {
                                "name": "org.apache.solr.client.solrj.SolrServerException",
                                "message": "Server refused connection at: http://solr-master:8983/solr",
                            },
                        },
                    ),
                )
                self.out.add(
                    end,
                    "ERROR",
                    BG_POD,
                    _app_line(
                        end,
                        "ERROR",
                        thread,
                        "de.hybris.platform.cronjob.jalo.CronJob",
                        f"Cronjob '{job}' finished with result ERROR",
                    ),
                )
            else:
                self.out.add(
                    end,
                    "INFO",
                    BG_POD,
                    _app_line(
                        end,
                        "INFO",
                        thread,
                        "de.hybris.platform.cronjob.jalo.CronJob",
                        f"CronJob {job} finished with result SUCCESS",
                    ),
                )
        gc = OUTAGE[0] - timedelta(minutes=1)
        self.out.add(
            gc,
            "INFO",
            API_PODS[1],
            "[gc] GC(8812) Pause Full (Allocation Failure) 3900M->3850M(4096M) 9123.456ms",
            container="platform",
        )
        for minute in range(0, 120, 3):
            t = T0 + timedelta(minutes=minute, seconds=rng.randint(0, 59))
            self.out.add(
                t,
                "INFO",
                BO_POD,
                _app_line(
                    t,
                    "INFO",
                    f"hybrisHTTP{rng.randint(1, 20)}",
                    "de.hybris.platform.servicelayer.session.impl.DefaultSessionService",
                    "Backoffice session heartbeat",
                ),
            )

    def generate(self, target_bytes: int) -> list[dict[str, Any]]:
        self.failed_payment(T0 + timedelta(minutes=31, seconds=12))
        self.failed_delivery(T0 + timedelta(minutes=44, seconds=5))
        self.b2b_account(T0 + timedelta(minutes=63, seconds=40))
        self.background()
        rng = self.rng
        while self.out.size < target_bytes:
            start = T0 + timedelta(seconds=rng.randint(0, 2 * 3600 - 600))
            if rng.random() < 0.3:
                code = str(rng.randint(1000000, 9999999))
                self.request(
                    start,
                    None,
                    None,
                    "GET",
                    f"/occ/v2/{SITE}/products/search?query=tv&page=0",
                    PRODUCT_FACADE,
                    "Product search 'tv'",
                )
                self.request(
                    start + timedelta(seconds=4),
                    None,
                    None,
                    "GET",
                    f"/occ/v2/{SITE}/products/{code}",
                    PRODUCT_FACADE,
                    f"Loading product {code}",
                )
                continue
            customer = rng.choice(self.customers[4:])
            self.shopping_journey(start, customer, rng.choice(customer.sessions))
        self.out.records.sort(key=lambda r: r["timestamp"])
        return self.out.records


def _uuid(rng: random.Random) -> str:
    h = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}"


def write_demo_export(path: Path, size_mb: float = 10.0, seed: int = 7) -> int:
    """Write a Grail-style JSON export of about ``size_mb`` megabytes; return the record count."""
    records = _Generator(seed).generate(int(size_mb * 1024 * 1024))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write('{"result": {"records": [\n')
        handle.write(",\n".join(json.dumps(r) for r in records))
        handle.write("\n]}}\n")
    return len(records)
