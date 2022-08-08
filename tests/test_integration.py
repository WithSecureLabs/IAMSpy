from iamspy import Model
import pathlib
import pytest


@pytest.mark.parametrize(
    "files,inp,out",
    [
        (
            {"gaads": ["basic-deny.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["basic-allow.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"], "resources": ["cross-account-rp.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                [],
                None,
                True,
            ),
            False,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
            ),
            True,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
                None,
                True,
            ),
            True,
        ),
    ],
)
def test_all(files, inp, out):
    m = Model()

    base_path = pathlib.Path(__file__).parent / "files"

    for gaad in files.get("gaads", []):
        m.load_gaad(base_path / gaad)

    for rp in files.get("resources", []):
        m.load_resource_policies(base_path / rp)

    assert m.can_i(*inp) == out
