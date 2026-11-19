import pytest
from django.contrib.admin import site
from django.test import RequestFactory
from rest_framework.decorators import api_view, permission_classes
from rest_framework.request import Request
from rest_framework.response import Response
from test_project.heroes.admin import HeroAPIKeyModelAdmin
from test_project.heroes.models import Hero, HeroAPIKey
from test_project.heroes.permissions import HasHeroAPIKey

from rest_framework_api_key.admin import APIKeyModelAdmin
from rest_framework_api_key.models import AbstractAPIKey, APIKey
from rest_framework_api_key.permissions import HasAPIKey

from .test_admin import build_admin_request

pytestmark = pytest.mark.django_db


@api_view()
@permission_classes([HasHeroAPIKey])
def custom_permission_view(request: Request) -> Response:
    return Response()


@api_view()
@permission_classes([HasAPIKey])
def library_permission_view(request: Request) -> Response:
    return Response()


def _status_code(view: object, rf: RequestFactory, key: str) -> int:
    request = rf.get("/test/", HTTP_AUTHORIZATION=f"Api-Key {key}")
    response = view(request)  # type: ignore[operator]
    return response.status_code


def _revoke_via_admin(
    rf: RequestFactory, model_admin: APIKeyModelAdmin, api_key: AbstractAPIKey
) -> None:
    """Revoke through the management page code path, not by direct DB update."""
    request = build_admin_request(rf)
    api_key.revoked = True
    model_admin.save_model(request, obj=api_key)


def test_revoking_one_of_two_keys_for_same_party(rf: RequestFactory) -> None:
    hero = Hero.objects.create(name="Batman")
    first, first_key = HeroAPIKey.objects.create_key(name="first", hero=hero)
    second, second_key = HeroAPIKey.objects.create_key(name="second", hero=hero)

    # Both keys work before any revocation.
    assert set(HeroAPIKey.objects.get_usable_keys().values_list("pk", flat=True)) == {
        first.pk,
        second.pk,
    }
    assert _status_code(custom_permission_view, rf, first_key) == 200
    assert _status_code(custom_permission_view, rf, second_key) == 200

    admin = HeroAPIKeyModelAdmin(HeroAPIKey, site)
    _revoke_via_admin(rf, admin, HeroAPIKey.objects.get(pk=first.pk))

    # 1. The usable-key lookup no longer returns the revoked record, while the
    #    other key of the same party is unaffected.
    usable = set(HeroAPIKey.objects.get_usable_keys().values_list("pk", flat=True))
    assert usable == {second.pk}
    assert HeroAPIKey.objects.is_valid(first_key) is False
    assert HeroAPIKey.objects.is_valid(second_key) is True
    with pytest.raises(HeroAPIKey.DoesNotExist):
        HeroAPIKey.objects.get_from_key(first_key)
    assert HeroAPIKey.objects.get_from_key(second_key).pk == second.pk

    # 2. The management page still lists the revoked record and reads back its
    #    real revocation state.
    request = build_admin_request(rf)
    listed = admin.get_queryset(request)
    assert listed.get(pk=first.pk).revoked is True
    assert listed.get(pk=second.pk).revoked is False
    assert "revoked" in admin.list_display

    # 3. The permission class uses the same validity rule, so the revoked key
    #    is rejected exactly like any other unusable key.
    assert _status_code(custom_permission_view, rf, first_key) == 403
    assert _status_code(custom_permission_view, rf, second_key) == 200


def test_library_and_custom_permissions_agree_on_revoked_key(
    rf: RequestFactory,
) -> None:
    hero = Hero.objects.create(name="Batman")
    _, hero_key = HeroAPIKey.objects.create_key(name="hero", hero=hero)
    _, library_key = APIKey.objects.create_key(name="library")

    # Both permission classes accept their own valid key to begin with.
    assert _status_code(library_permission_view, rf, library_key) == 200
    assert _status_code(custom_permission_view, rf, hero_key) == 200

    hero_api_key = HeroAPIKey.objects.get_from_key(hero_key)
    _revoke_via_admin(rf, HeroAPIKeyModelAdmin(HeroAPIKey, site), hero_api_key)

    library_api_key = APIKey.objects.get_from_key(library_key)
    library_api_key.revoked = True
    library_api_key.save()

    # Both the library-provided and the custom permission classes deny a
    # revoked key, in the same way they deny any invalid key.
    assert _status_code(library_permission_view, rf, library_key) == 403
    assert _status_code(custom_permission_view, rf, hero_key) == 403

    # The refusal response keeps the current format and leaks nothing.
    response = library_permission_view(
        rf.get("/test/", HTTP_AUTHORIZATION=f"Api-Key {library_key}")
    )
    body = str(response.data)
    assert library_key not in body
    assert library_key.partition(".")[0] not in body
    assert library_api_key.hashed_key not in body


def test_unknown_prefix_is_denied_without_lookup_errors(rf: RequestFactory) -> None:
    hero = Hero.objects.create(name="Batman")
    _, key = HeroAPIKey.objects.create_key(name="test", hero=hero)

    # Well-formed key whose prefix was never issued.
    unknown_prefix = "zzzzzzzz"
    assert not HeroAPIKey.objects.filter(prefix=unknown_prefix).exists()
    unknown_key = f"{unknown_prefix}.{'a' * 32}"

    with pytest.raises(HeroAPIKey.DoesNotExist):
        HeroAPIKey.objects.get_from_key(unknown_key)
    assert HeroAPIKey.objects.is_valid(unknown_key) is False

    assert _status_code(custom_permission_view, rf, unknown_key) == 403
    # The known key is untouched by the unknown-prefix lookup.
    assert _status_code(custom_permission_view, rf, key) == 200


def test_revoking_twice_keeps_access_revoked(rf: RequestFactory) -> None:
    hero = Hero.objects.create(name="Batman")
    api_key, key = HeroAPIKey.objects.create_key(name="test", hero=hero)
    admin = HeroAPIKeyModelAdmin(HeroAPIKey, site)

    # Two revocations of the same record must be idempotent.
    _revoke_via_admin(rf, admin, HeroAPIKey.objects.get(pk=api_key.pk))
    _revoke_via_admin(rf, admin, HeroAPIKey.objects.get(pk=api_key.pk))

    refreshed = HeroAPIKey.objects.get(pk=api_key.pk)
    assert refreshed.revoked is True
    assert HeroAPIKey.objects.is_valid(key) is False
    assert _status_code(custom_permission_view, rf, key) == 403
